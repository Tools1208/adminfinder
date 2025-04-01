#!/usr/bin/python3
# coding=utf-8

__AUTHOR__ = "Fnkoc"
__DATE__ = "27/02/17"
__VERSION__ = "0.8.7"
__GITHUB__ = "https://github.com/fnk0c"

"""
    Copyright (C) 2015  Franco Colombino
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
"""

from sys import path, argv
import argparse
path.append("src")
import connection
import scans
from time import sleep
from threading import Thread, active_count


def check_target(target, UserAgent, tor):
    if tor:
        connection.tor().connect()
    
    conn = connection.conn(target, UserAgent)
    HTTPcode = conn.HTTPcode()
    if HTTPcode == 200:
        print(f"Server status: Online ({HTTPcode})")
    else:
        print(f"Server status: Offline ({HTTPcode})")
        exit()

    redirect = conn.redirect()
    if target != redirect:
        print(f"Redirected: {redirect}")
        answer = input("Follow redirection? [y/N] ").lower()
        
        if answer in ("n", ""):
            return target
        elif answer == "y":
            print(f"\nNew target: {redirect}")
            return redirect
    else:
        return target


class Brute:
    def __init__(self, target, paths, ext, UserAgent, tor, found, subdomain):
        self.target = target
        self.paths = paths
        self.ext = ext
        self.UserAgent = UserAgent
        self.tor = tor
        self.found = found
        self.subdomain = subdomain

    def its_time(self, url_target):
        conn = connection.conn(url_target, self.UserAgent)
        HTTPcode = conn.HTTPcode()

        if HTTPcode == 200:
            print(f"Found: {url_target} >> ({HTTPcode})")
            self.found.append(url_target)
        elif HTTPcode == 301:
            print(f"Redirected: {url_target} >> ({HTTPcode})")
        elif HTTPcode == 404:
            if args.v:
                print(f"{url_target} >> {HTTPcode}")

    def start(self):
        for self.path in self.paths:
            self.path = self.path.rstrip()

            if self.path not in self.scanned:
                if self.ext:
                    if "." in self.path:
                        if self.ext in self.path:
                            self.its_time(f"{self.target}/{self.path}")
                    else:
                        self.its_time(f"{self.target}/{self.path}")
                else:
                    self.its_time(f"{self.target}/{self.path}")
                self.scanned.append(self.path)

    def run(self, t):
        self.scanned = []

        for _ in range(t):
            Thread(target=self.start).start()
            sleep(1.2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fast and powerful admin finder", add_help=False)

    parser.add_argument("-h", "--help", help="Shows this message and exits", action="store_true")
    parser.add_argument("-u", help="target site", type=str)
    parser.add_argument("-w", help="set wordlist (default: wl_medium)", default="./wordlists/wl_medium")
    parser.add_argument("-t", help="set threads number (default: 5)", default=5, type=int)
    parser.add_argument("-v", help="enable verbose", default=False, action="store_true")
    parser.add_argument("--ext", help="filter path by target extension", default=False)
    parser.add_argument("--user-agent", help="modify user-agent", default=False, action="store_true", dest="UserAgent")
    parser.add_argument("--sub-domain", action="store_true", dest="sub", help="Search for subdomains instead of directories")
    parser.add_argument("--tor", help="set TOR proxy", default=False, action="store_true", dest="tor")
    parser.add_argument("--search", help="use google and duckduckgo to search", action="store_true")
    parser.add_argument("--dork", help="set custom dork", default=None)
    parser.add_argument("--nmap", help="use nmap to scan ports and services", nargs="?", default=False)
    args = parser.parse_args()

    if len(argv) <= 1 or args.help:
        parser.print_help()
        exit()

    if not args.u:
        parser.print_help()
        print("\ncangibrina.py: error: argument -u is required\n")
        exit()

    print("\n")
    print("*" * 80)

    if not args.u.startswith("http://") and not args.u.startswith("https://"):
        target = f"http://{args.u}"
    else:
        target = args.u

    target_result = check_target(target, args.UserAgent, args.tor)

    try:
        with open(args.w, "r") as wordlist:
            paths = wordlist.readlines()
    except FileNotFoundError:
        print(f"Error: Wordlist file '{args.w}' not found.")
        exit()

    found = []
    print(" [+] Testing...")

    b = Brute(target_result, paths, args.ext, args.UserAgent, args.tor, found, args.sub)
    b.run(args.t)

    while True:
        if active_count() == 1:
            if args.search:
                s = scans.passive(target_result, args.dork)
                s.google()
                s.DuckDuckGo()

            if args.nmap:
                n = scans.active(target_result.replace("http://", "").replace("https://", ""))
                if args.nmap is None:
                    n.nmap("sudo nmap -v -sS -sC")
                else:
                    n.nmap(args.nmap)

            robots = f"{target_result}/robots.txt"
            rob_code = connection.conn(robots, args.UserAgent).HTTPcode()
            if rob_code == 200:
                print(f"Found: {robots} >> ({rob_code})")
                found.append(robots)
            elif args.v:
                print(f"{robots} >> {rob_code}")

            print("*" * 80)
            print("\t[RESULTS]")
            for k in found:
                print(k)
            break
        else:
            sleep(1)
