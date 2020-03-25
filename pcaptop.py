import click
import curses
import dpkt
import logging
import socket
import sys

from contextlib import contextmanager
from contextlib import closing
from expiringdict import ExpiringDict


LOG = logging.getLogger(__name__)


class App(object):
    def __init__(self, screen, pktfd):
        self.screen = screen
        self.screen.nodelay(1)
        self.pktfd = pktfd
        self.draw_windows()
        self.flows = ExpiringDict(max_len=1000, max_age_seconds=300)

    def draw_windows(self):
        height, width = self.screen.getmaxyx()
        LOG.debug('screen size %s x %s', height, width)
        self.content_height = height - 3 - 3

        self.screen.clear()
        self.win_header = curses.newwin(3, width)
        self.win_content = curses.newwin(self.content_height, width, 3, 0)
        self.win_status = curses.newwin(3, width, self.content_height + 3, 0)
        self.win_header.box()
        self.win_content.box()
        self.win_status.box()

        self.win_header.addstr(
            1, 1, '{:<15} {:<6} -> {:<15} {:<6} {:<10} {:<10}'.format(
                'src', 'sport', 'dst', 'dport',
                'packets', 'bytes'))

        self.screen.noutrefresh()
        self.win_header.noutrefresh()
        self.win_content.noutrefresh()
        self.win_status.noutrefresh()
        curses.doupdate()

    def set_status(self, message, clear=False):
        if clear:
            self.win_status.clear()
        self.win_status.box()
        self.win_status.addstr(1, 1, message)
        self.win_status.noutrefresh()

    def loop(self):
        packets = dpkt.pcap.Reader(self.pktfd)
        pcnt = 0

        while True:
            ch = self.screen.getch()
            if ch == ord('q'):
                break
            elif ch == curses.KEY_RESIZE:
                LOG.debug('resize!')
                self.draw_windows()

            try:
                ts, buf = next(packets)
                pcnt += 1
                self.set_status('Read {} packets'.format(pcnt))
            except StopIteration:
                self.screen.nodelay(0)
                self.set_status('No more packets.', clear=True)
                continue

            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except dpkt.dpkt.NeedData:
                LOG.warning('failed to read packet: %s', buf)
                continue

            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            if not isinstance(eth.ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                continue

            src = (socket.inet_ntoa(eth.ip.src), eth.ip.data.sport)
            dst = (socket.inet_ntoa(eth.ip.dst), eth.ip.data.dport)
            key = (src, dst)

            self.flows.setdefault(key,
                                  {'packets': 0, 'bytes': 0})['packets'] += 1
            self.flows[key]['bytes'] += len(eth.ip.data)

            for i, flow in enumerate(
                    reversed(
                        sorted(self.flows.items(), key=lambda x: x[1]['bytes'])
                    )
            ):
                if i >= self.content_height - 2:
                    break

                self.win_content.addstr(
                    i+1, 1,
                    '{:<15} {:<6} -> {:<15} {:<6} {:<10} {:<10}'.format(
                        flow[0][0][0], flow[0][0][1],
                        flow[0][1][0], flow[0][1][1],
                        flow[1]['packets'], flow[1]['bytes'],
                    )
                )

            self.win_content.noutrefresh()
            curses.doupdate()


@contextmanager
def sanity():
    stdscr = curses.initscr()
    curses.noecho()
    curses.cbreak()
    stdscr.keypad(True)
    try:
        yield stdscr
    finally:
        curses.nocbreak()
        curses.echo()
        stdscr.keypad(False)
        curses.endwin()


@click.command()
@click.option('-l', '--log-file')
@click.argument('input_file',
                type=click.File('rb'),
                )
def main(log_file, input_file):
    if log_file:
        logging.basicConfig(
            level='DEBUG',
            filename='pcaptop.log',
        )

    with sanity() as stdscr, closing(input_file) as fd:
        app = App(stdscr, fd)
        app.loop()


if __name__ == '__main__':
    main()
