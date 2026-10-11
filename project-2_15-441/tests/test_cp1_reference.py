#!/usr/bin/env python3


import os
from pathlib import Path
import random
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
HEADER = struct.Struct('!IHHIIHHBHH')
SYN, ACK = 8, 4
MASK = 0xffffffff
TIMEOUT_MS = int(os.environ.get('CP1_TEST_TIMEOUT', '120'))
WINDOW = int(os.environ.get('CP1_TEST_WINDOW', str(1375 * 32)))
MSS = 1375


def wire(src, dst, seq=0, ack=0, flags=0, data=b'', **changes):
    values = dict(identifier=15441, src=src, dst=dst, seq=seq & MASK,
                  ack=ack & MASK, hlen=25, plen=25 + len(data), flags=flags,
                  adv=1, ext=0)
    values.update(changes)
    return HEADER.pack(*values.values()) + data


def unpack(data):
    values = HEADER.unpack(data[:25])
    assert values[0] == 15441 and values[5] == 25 and values[6] == len(data)
    assert len(data) <= 1400
    return dict(src=values[1], dst=values[2], seq=values[3], ack=values[4],
                flags=values[7], data=data[25:])


class CP1(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory()
        path = Path(cls.build.name)
        shutil.copytree(ROOT / 'inc', path / 'inc')
        grading = path / 'inc/grading.h'
        text = grading.read_text().replace('#define DEFAULT_TIMEOUT 3000',
                                          f'#define DEFAULT_TIMEOUT {TIMEOUT_MS}')
        text = text.replace('#define CP1_WINDOW_SIZE (MSS * 32)',
                            f'#define CP1_WINDOW_SIZE {WINDOW}')
        grading.write_text(text)
        cls.exe = path / 'endpoint'
        flags = os.environ.get('CP1_TEST_CFLAGS', '').split()
        subprocess.run(['gcc', '-Wall', '-Wextra', '-Werror', '-pedantic', '-g',
                        '-pthread', '-DCP1_TESTING', *flags, '-I' + str(path / 'inc'),
                        str(ROOT / 'tests/cp1_endpoint.c'),
                        str(ROOT / 'src/backend.c'), str(ROOT / 'src/cmu_tcp.c'),
                        str(ROOT / 'src/cmu_packet.c'), '-o', str(cls.exe)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.processes = []
        self.sockets = []

    def tearDown(self):
        for p in self.processes:
            if p.poll() is None:
                p.kill()

            p.communicate()
        for s in self.sockets:
            s.close()
        self.tmp.cleanup()

    def udp(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('127.0.0.1', 0))
        s.settimeout(max(.03, TIMEOUT_MS / 1000 * 3))
        self.sockets.append(s)
        return s

    def app(self, listener, port, data=b'', receive=0, isn=None):
        index = len(self.processes)
        input_path = Path(self.tmp.name) / f'in{index}'
        output_path = Path(self.tmp.name) / f'out{index}'

        input_path.write_bytes(data)
        env = os.environ.copy()
        if isn is not None:
            env['CP1_TEST_ISN'] = str(isn)
        p = subprocess.Popen([str(self.exe), str(int(listener)), str(port),
                              str(input_path), str(receive), str(output_path)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        self.processes.append(p)
        return p, output_path

    def done(self, p, timeout=8):
        out, err = p.communicate(timeout=timeout)
        self.assertEqual(p.returncode, 0, err.decode(errors='replace'))
        self.assertIn(b'RECEIVED', out)

    def recv(self, s):
        data, addr = s.recvfrom(65535)
        return unpack(data), addr

    def initiate(self, s, send=b'', receive=0, peer_isn=900, isn=None):
        p, output = self.app(False, s.getsockname()[1], send, receive, isn)
        syn, addr = self.recv(s)

        self.assertEqual(syn['flags'], SYN)
        self.assertEqual(syn['ack'], 0)
        self.assertEqual(syn['dst'], s.getsockname()[1])
        self.assertEqual(syn['src'], addr[1])
        s.sendto(wire(s.getsockname()[1], addr[1], peer_isn,
                      syn['seq'] + 1, SYN | ACK), addr)
        ack, _ = self.recv(s)
        self.assertEqual(ack['flags'], ACK)
        self.assertEqual(ack['seq'], (syn['seq'] + 1) & MASK)
        self.assertEqual(ack['ack'], (peer_isn + 1) & MASK)
        return p, output, syn, addr

    def listen(self, s, send=b'', receive=1, peer_isn=900, isn=None):

        reserve = self.udp()
        port = reserve.getsockname()[1]
        reserve.close()
        p, output = self.app(True, port, send, receive, isn)
        addr = ('127.0.0.1', port)
        time.sleep(.05)
        s.sendto(wire(s.getsockname()[1], port, peer_isn, flags=SYN), addr)
        synack, _ = self.recv(s)
        self.assertEqual(synack['flags'], SYN | ACK)
        self.assertEqual(synack['ack'], (peer_isn + 1) & MASK)
        s.sendto(wire(s.getsockname()[1], port, peer_isn + 1,
                      synack['seq'] + 1, ACK), addr)
        return p, output, synack, addr

    def test_initiator_retries_and_rejects_bad_synack(self):
        s = self.udp()
        p, output = self.app(False, s.getsockname()[1], receive=1)
        syn, addr = self.recv(s)
        again, _ = self.recv(s)

        self.assertEqual(again, syn)
        bad = wire(s.getsockname()[1], addr[1], 90, syn['seq'], SYN | ACK)
        s.sendto(bad, addr)
        again, _ = self.recv(s)
        self.assertEqual(again['flags'], SYN)
        s.sendto(wire(s.getsockname()[1], addr[1], 90, syn['seq'] + 1, SYN | ACK), addr)
        final, _ = self.recv(s)
        self.assertEqual(final['ack'], 91)

        s.sendto(wire(s.getsockname()[1], addr[1], 90, syn['seq'] + 1, SYN | ACK), addr)
        repeated, _ = self.recv(s)
        self.assertEqual(repeated, final)
        s.sendto(wire(s.getsockname()[1], addr[1], 91, data=b'x'), addr)
        ack, _ = self.recv(s)
        self.assertEqual(ack['ack'], 92)
        self.done(p)
        self.assertEqual(output.read_bytes(), b'x')

    def test_listener_invalid_packets_and_retries(self):
        s = self.udp()
        reserve = self.udp()
        port = reserve.getsockname()[1]
        reserve.close()
        p, output = self.app(True, port, receive=1)
        addr = ('127.0.0.1', port)
        time.sleep(.05)
        for packet in [b'x', wire(s.getsockname()[1], port, flags=SYN, identifier=0),
                       wire(s.getsockname()[1], port, flags=SYN, plen=100),
                       wire(s.getsockname()[1], port, flags=SYN, data=b'x'),
                       wire(s.getsockname()[1], port, flags=ACK)]:
            s.sendto(packet, addr)
        with self.assertRaises(socket.timeout):
            self.recv(s)
        s.sendto(wire(s.getsockname()[1], port, 80, flags=SYN), addr)
        synack, _ = self.recv(s)
        repeated, _ = self.recv(s)
        self.assertEqual(repeated, synack)
        s.sendto(wire(s.getsockname()[1], port, 81, synack['seq'], ACK), addr)
        repeated, _ = self.recv(s)
        self.assertEqual(repeated['flags'], SYN | ACK)
        s.sendto(wire(s.getsockname()[1], port, 82, synack['seq'] + 1, ACK), addr)
        repeated, _ = self.recv(s)
        self.assertEqual(repeated['flags'], SYN | ACK)
        s.sendto(wire(s.getsockname()[1], port, 81, synack['seq'] + 1, ACK), addr)
        s.sendto(wire(s.getsockname()[1], port, 81, data=b'z'), addr)
        ack, _ = self.recv(s)
        self.assertEqual(ack['ack'], 82)
        self.done(p)
        self.assertEqual(output.read_bytes(), b'z')

    def test_receive_order_duplicates_wrap_and_malformed(self):
        s = self.udp()
        p, output, synack, addr = self.listen(s, receive=6, peer_isn=MASK - 2)
        seq = MASK - 1
        src, dst = s.getsockname()[1], addr[1]
        for malformed in [b'bad', wire(src, dst, seq, data=b'bad', hlen=24),
                          wire(src, dst, seq, data=b'bad', ext=4),
                          wire(src, dst, seq, data=b'bad', plen=24),
                          wire(src + 1, dst, seq, data=b'bad'),
                          wire(src, dst, seq, data=b'bad', flags=1),
                          b'x' * 1401]:
            s.sendto(malformed, addr)
        outsider = self.udp()
        outsider.sendto(wire(outsider.getsockname()[1], dst, seq, data=b'bad'), addr)
        s.sendto(wire(src, dst, seq + 3, data=b'def'), addr)
        ack, _ = self.recv(s)
        self.assertEqual(ack['ack'], seq)
        s.sendto(wire(src, dst, seq, data=b'abc'), addr)
        ack, _ = self.recv(s)
        self.assertEqual(ack['ack'], 1)
        s.sendto(wire(src, dst, seq, data=b'abc'), addr)
        ack, _ = self.recv(s)
        self.assertEqual(ack['ack'], 1)
        s.sendto(wire(src, dst, 1, data=b'def'), addr)
        ack, _ = self.recv(s)
        self.assertEqual(ack['ack'], 4)
        self.done(p)
        self.assertEqual(output.read_bytes(), b'abcdef')

    def test_fixed_window_slides_and_go_back_n(self):
        s = self.udp()
        content = bytes((i * 7) % 256 for i in range(WINDOW * 2 + 31))
        p, _, syn, addr = self.initiate(s, send=content, isn=MASK - 10)
        start = (syn['seq'] + 1) & MASK
        outstanding = []
        sent = 0
        while sent < WINDOW:
            packet, _ = self.recv(s)
            self.assertEqual(packet['seq'], (start + sent) & MASK)
            outstanding.append(packet)
            sent += len(packet['data'])
        self.assertEqual(sent, WINDOW)

        s.sendto(wire(s.getsockname()[1], addr[1], 901, start + WINDOW + 1, ACK), addr)
        resent = 0
        while resent < WINDOW:
            repeated, _ = self.recv(s)
            self.assertEqual(repeated['seq'], (start + resent) & MASK)
            self.assertEqual(repeated['data'],
                             content[resent:resent + len(repeated['data'])])
            resent += len(repeated['data'])
        self.assertEqual(resent, WINDOW)
        first_len = len(outstanding[0]['data'])
        s.sendto(wire(s.getsockname()[1], addr[1], 901, start + first_len, ACK), addr)
        new, _ = self.recv(s)
        self.assertEqual(new['seq'], (start + WINDOW) & MASK)
        self.assertEqual(len(new['data']), first_len)

        accepted = WINDOW + first_len
        s.sendto(wire(s.getsockname()[1], addr[1], 901, start + accepted, ACK), addr)
        while accepted < len(content):
            packet, _ = self.recv(s)
            distance = (packet['seq'] - start) & MASK
            if distance == accepted:
                self.assertEqual(packet['data'], content[accepted:accepted + len(packet['data'])])
                accepted += len(packet['data'])
            s.sendto(wire(s.getsockname()[1], addr[1], 901, start + accepted, ACK), addr)
        self.done(p)

    def test_lost_final_data_ack_close_linger(self):
        s = self.udp()
        p, output, _, addr = self.listen(s, receive=1)
        data = wire(s.getsockname()[1], addr[1], 901, data=b'k')
        s.sendto(data, addr)
        first, _ = self.recv(s)
        
        time.sleep(TIMEOUT_MS / 1000 * 1.1)
        s.sendto(data, addr)
        second, _ = self.recv(s)
        self.assertEqual(second['ack'], first['ack'])
        self.done(p)
        self.assertEqual(output.read_bytes(), b'k')

    def test_listener_duplicate_syn_and_random_sequences(self):
        sequences = []
        for _ in range(4):
            s = self.udp()
            p, output, synack, addr = self.listen(s, receive=1)
            sequences.append(synack['seq'])
            s.sendto(wire(s.getsockname()[1], addr[1], 901, data=b'r'), addr)
            self.recv(s)
            self.done(p)
            self.assertEqual(output.read_bytes(), b'r')
        self.assertEqual(len(set(sequences)), len(sequences))

        s = self.udp()
        reserve = self.udp()
        port = reserve.getsockname()[1]
        reserve.close()
        p, _ = self.app(True, port, receive=1)
        addr = ('127.0.0.1', port)
        time.sleep(.05)
        syn = wire(s.getsockname()[1], port, 500, flags=SYN)
        s.sendto(syn, addr)
        first, _ = self.recv(s)
        s.sendto(syn, addr)
        again, _ = self.recv(s)

        self.assertEqual(again, first)
        s.sendto(wire(s.getsockname()[1], port, 501, first['seq'] + 1, ACK), addr)
        s.sendto(wire(s.getsockname()[1], port, 501, data=b'r'), addr)
        self.recv(s)
        self.done(p)

    def test_pure_ack_no_ack_loop_and_combined_ack_data(self):
        s = self.udp()
        p, output, syn, addr = self.initiate(s, send=b'hello', receive=3)
        data, _ = self.recv(s)
        self.assertEqual(data['data'], b'hello'[:len(data['data'])])

        count = len(data['data'])
        while count < 5:
            s.sendto(wire(s.getsockname()[1], addr[1], 901, syn['seq'] + 1 + count, ACK), addr)
            data, _ = self.recv(s)
            count += len(data['data'])
        s.sendto(wire(s.getsockname()[1], addr[1], 901, syn['seq'] + 6, ACK), addr)

        with self.assertRaises(socket.timeout):
            self.recv(s)
        s.sendto(wire(s.getsockname()[1], addr[1], 901, syn['seq'] + 6, ACK, b'bye'), addr)
        ack, _ = self.recv(s)
        self.assertEqual(ack['ack'], 904)
        self.done(p)
        self.assertEqual(output.read_bytes(), b'bye')

    def test_random_initial_sequences(self):
        sequences = []
        for _ in range(5):
            s = self.udp()
            p, _, syn, addr = self.initiate(s, receive=1)
            s.sendto(wire(s.getsockname()[1], addr[1], 901, data=b'x'), addr)
            self.recv(s)
            sequences.append(syn['seq'])
            self.done(p)
        self.assertEqual(len(set(sequences)), len(sequences))

    def test_simultaneous_bidirectional_transfer_with_loss(self):


        proxy = self.udp()
        reserve = self.udp()
        server_port = reserve.getsockname()[1]
        reserve.close()
        size = max(4099, min(250003, WINDOW * 6 + 31))
        a = random.Random(44).randbytes(size)
        b = random.Random(55).randbytes(size + 111)
        server, server_out = self.app(True, server_port, b, len(a))
        time.sleep(.05)
        client, client_out = self.app(False, proxy.getsockname()[1], a, len(b))
        server_addr = ('127.0.0.1', server_port)
        client_addr = None
        rng = random.Random(614)
        deadline = time.monotonic() + max(20, TIMEOUT_MS / 1000 * 150)
        while server.poll() is None or client.poll() is None:
            self.assertLess(time.monotonic(), deadline, 'lossy transfer stalled')
            try:
                data, source = proxy.recvfrom(65535)
            except socket.timeout:
                continue
            packet = unpack(data)
            if source == server_addr:
                target = client_addr
            else:
                client_addr = source
                target = server_addr
            if target is None or rng.random() < .12:
                continue

            forwarded = wire(proxy.getsockname()[1], target[1], packet['seq'],
                             packet['ack'], packet['flags'], packet['data'])
            proxy.sendto(forwarded, target)
            if rng.random() < .05:
                proxy.sendto(forwarded, target)

        self.done(client)
        self.done(server)
        self.assertEqual(server_out.read_bytes(), a)
        self.assertEqual(client_out.read_bytes(), b)

    def test_large_bidirectional_lossless_transfer(self):
        reserve = self.udp()
        port = reserve.getsockname()[1]
        reserve.close()

        a = random.Random(90).randbytes(1000003)
        b = random.Random(91).randbytes(1000117)

        server, server_out = self.app(True, port, b, len(a))
        time.sleep(.05)
        client, client_out = self.app(False, port, a, len(b))
        self.done(client, timeout=max(20, TIMEOUT_MS / 1000 * 50))
        self.done(server)
        self.assertEqual(server_out.read_bytes(), a)
        self.assertEqual(client_out.read_bytes(), b)


if __name__ == '__main__':
    unittest.main(verbosity=2)


