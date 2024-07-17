# -*- fill-column: 100; -*-

# ZTE MC888 5G router statistics logger
#
# Copyright (c) 2024 Steven Flintham
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
# associated documentation files (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge, publish, distribute,
# sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or
# substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
# NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
# OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


# I didn't want to split this into modules to make it easy to run without fiddling with PYTHONPATH,
# so "# === blah" comments indicate groups of related bits of code.
#
# This is written for Python 3. I would have liked to support Python 2 as well but I am running into
# all sorts of gratuitous little incompatibilities. Since I have to make a choice, it seems better
# to go with Python 3 - particularly given this code can download from arbitrary websites and thus
# we want timely security patches. I suspect it would not be hard to make this run under Python 2 if
# you were willing to break Python 3 compatibility.


import argparse
import configparser
import csv
import datetime
import hashlib
import itertools
import json
import os
import random
import requests
import sys
import time


# === Utilities


megabyte = 1024 * 1024
gigabyte = megabyte * 1024

def die(s):
    print(s, file=sys.stderr)
    sys.exit(1)

def log_exception(e):
    print(str(e), file=sys.stderr)

def log_verbose(s):
    if cmd_args.verbose:
        print(s, file=sys.stderr)

def log_error(s):
    print(s, file=sys.stderr)


# === Command line and config file parsing


app_data = os.environ.get("AppData")
if app_data is not None:
    default_config_file = os.path.join(app_data, "bbsrc")
else:
    default_config_file = os.path.join(os.path.expanduser("~"), ".bbsrc")

parser = argparse.ArgumentParser(
    description="Log broadband statistics from a ZTE MC888 router to a file for later analysis.")
parser.add_argument("-c", "--config", metavar="FILE",
                    help="specify config file (default %s)" % default_config_file)
parser.add_argument("-v", "--verbose", action="store_true", help="increase verbosity of logging")
parser.add_argument("-f", "--file", metavar="FILE", help="specify statistics CSV file")
parser.add_argument("-d", "--download", action="store_true", help="perform a test download")
parser.add_argument("-p", "--download-probability", metavar="P",
                    help="perform a test download with probability P%%")
parser.add_argument("--polite", action="store_true",
                    help="try to avoid disconnecting existing router GUI sessions")
cmd_args = parser.parse_args()
config_file = default_config_file if cmd_args.config is None else cmd_args.config


class Config:
    def __init__(self, config_file, cmd_args):
        config_parser = configparser.ConfigParser()

        try:
            with open(config_file, "r") as f:
                log_verbose("Using config file %s" % config_file)
                config_parser.read_file(f)
                self.router_address = config_parser.get("router", "address")
                self.router_username = config_parser.get("router", "username")

                environ_password = os.environ.get("BBS_PASSWORD")
                if environ_password is not None:
                    log_verbose("Using password from BBS_PASSWORD environment variable")
                    self.router_password = environ_password
                else:
                    if config_parser.has_option("router", "password"):
                        log_verbose("Using password from config file")
                        self.router_password = config_parser.get("router", "password")
                    else:
                        die("Password must be specified in the BBS_PASSWORD environment variable "
                            "or in the config file")

                if cmd_args.file is not None:
                    self.csv_file = cmd_args.file
                    log_verbose("Using CSV file from command line")
                else:
                    if config_parser.has_option("statistics", "file"):
                        self.csv_file = config_parser.get("statistics", "file")
                        log_verbose("Using CSV file from config file")
                    else:
                        die("CSV file must be specified on the command line or in the config file")
                if config_parser.has_option("statistics", "tempfile"):
                    self.temp_csv_file = config_parser.get("statistics", "tempfile")
                else:
                    self.temp_csv_file = self.csv_file + "~"
                self.suppressed_csv_keys = set()
                if config_parser.has_option("statistics", "suppress_columns"):
                    suppress_columns = config_parser.get("statistics", "suppress_columns")
                    suppress_columns = suppress_columns.replace("\n", ",").split(",")
                    for csv_key in suppress_columns:
                        csv_key = csv_key.strip()
                        if csv_key == "":
                            continue
                        self.suppressed_csv_keys.add(csv_key.strip())

                self.test_download_url_list = []
                if config_parser.has_option("tests", "testurls"):
                    for item in config_parser.get("tests", "testurls").splitlines():
                        item = item.strip()
                        if item == "" or item.startswith("#"):
                            continue
                        inline_comment_index = item.find(" #")
                        if inline_comment_index > -1:
                            item = item[:inline_comment_index]
                        inline_comment_index = item.find("\t#")
                        if inline_comment_index > -1:
                            item = item[:inline_comment_index]
                        self.test_download_url_list.append(item)

                if (len(self.test_download_url_list) == 0
                        and (cmd_args.download or cmd_args.download_probability)):
                    die("Download option specified but no list of test download URLs available")

                if cmd_args.download_probability is not None:
                    # TODO: We always interpret this as a percentage even if there is no % sign.  We
                    # could treat %-less values as a probability and insist on the range 0-1, but
                    # this is probably more confusing than helpful.
                    probability = cmd_args.download_probability.strip()
                    if probability.endswith("%"):
                        probability = probability[:-1]
                    try:
                        probability = int(probability)
                    except ValueError:
                        die("Invalid argument to --download-probability: %s" %
                            cmd_args.download_probability)
                    if probability < 0 or probability > 100:
                        die("Download probability must be between 0 and 100")
                    cmd_args.download = probability >= random.SystemRandom().randint(1, 100)
        except (configparser.NoOptionError, configparser.ParsingError) as e:
            die("Bad config file: " + str(e))
        except FileNotFoundError:
            die("Config file not found")


config = Config(config_file, cmd_args)
test_download_url = ""
if cmd_args.download:
    i = random.SystemRandom().randint(0, len(config.test_download_url_list) - 1)
    test_download_url = config.test_download_url_list[i]


# === Router web API interaction


# Authenticate to the router's web interface, returning a requests.Session object if authentication
# succeeded and raising an exception if not.
#
# addr should be the IP address of the router.
def start_session(addr, user, password, polite=False):
    session = requests.Session()
    session.headers.update({
            "Referer": "http://%s/" % addr,
            "Host": addr
    })

    # Only one user is allowed to be connected to the router's web GUI at a time, so if someone else
    # is already connected (most likely the user in a web browser), we will forcibly disconnect them
    # if we connect. In polite mode we try to fail rather than kick other users out. I haven't been
    # able to find a way to do this reliably, but login_lock_time decreases from 300 (seconds) to
    # -1 after someone logs in. (Logging out does not affect this.) If we only authenticate when
    # this is negative, we therefore shouldn't kick anyone out until they have been logged in for
    # 300 seconds. Our own logins count, of course, so polite mode cannot be used if you want to
    # log more frequently than every 300ish seconds.
    if polite:
        params_response = session.get("http://%s/goform/goform_get_cmd_process" % addr, params={
            "isTest": "false",
            "multi_data": "1",
            "cmd": "login_lock_time",
        })
        params_response.raise_for_status()
        login_lock_time = params_response.json().get("login_lock_time")
        if login_lock_time is not None and int(login_lock_time) > 0:
            raise RuntimeError("Another login happened recently, not connecting")

    # Get the router's challenge.
    now = int(time.time() * 1000)
    challenge_response = session.get("http://%s/goform/goform_get_cmd_process" % addr, params={
            "isTest": "false",
            "cmd": "LD",
            "_": str(now)
    })
    challenge_response.raise_for_status()
    challenge_string = challenge_response.json().get("LD")
    if challenge_string is None:
        raise RuntimeError("Didn't receive challenge from router")

    # Respond to the router's challenge.
    def sha256(s):
        m = hashlib.sha256()
        m.update(bytes(s, "ascii"))
        return m.hexdigest().upper()
    response_response = session.post("http://%s/goform/goform_set_cmd_process" % addr, data={
        "isTest": "false",
        "goformId": "LOGIN",
        "user": user,
        "password": sha256(sha256(password) + challenge_string)
    })
    response_response.raise_for_status()
    authentication_result = response_response.json().get("result")
    if authentication_result is None:
        raise RuntimeError("Didn't receive authentication result from router")
    authentication_result = str(authentication_result)
    if authentication_result == "3":
        raise RuntimeError("Invalid password")
    elif authentication_result != "0":
        raise RuntimeError("Authentication failed (result %s)" % authentication_result)
    session.addr = addr
    return session


def get_raw_router_values(session, router_keys):
    params_response = session.get("http://%s/goform/goform_get_cmd_process" % session.addr, params={
        "isTest": "false",
        "multi_data": "1",
        "cmd": ",".join(router_keys)
    })
    params_response.raise_for_status()
    return params_response.json()


# === Router statistic parsing, derivation and formatting


class Statistic(object):
    def __init__(self, csv_key, router_keys, desc, hide):
        assert isinstance(router_keys, list)
        self.csv_key = csv_key
        self.router_keys = router_keys
        self.desc = desc
        self.hide = hide

    def log_parse_error(self, string_value, e):
        # We expect len(self.router_keys) == 1, but since this is error  andling
        # code let's accommodate the more general case.
        log_error("Error parsing key '%s' with value '%s': %s"
                  % ("/".join(self.router_keys), string_value, str(e)))


class SimpleStatistic(Statistic):
    def __init__(self, router_key, desc, fmt, hide, csv_key):
        Statistic.__init__(
            self, router_key if csv_key is None else csv_key, [router_key], desc, hide)
        assert len(self.router_keys) == 1
        self.fmt = fmt

    def csv_str(self, simple_statistics):
        value = simple_statistics[self.router_keys[0]]
        return "" if value is None else self.fmt % value


class StringStatistic(SimpleStatistic):
    def __init__(self, router_key, desc, hide=False, csv_key=None):
        SimpleStatistic.__init__(self, router_key, desc, "%s", hide, csv_key)

    def parse_router_value(self, string_value):
        return string_value


class DecimalStatistic(SimpleStatistic):
    def __init__(self, router_key, desc, fmt=None, hide=False, csv_key=None, divisor=1.0):
        SimpleStatistic.__init__(self, router_key, desc, fmt, hide, csv_key)
        self.divisor = divisor

    def parse_router_value(self, string_value):
        if string_value == "":
            return None
        try:
            string_value = string_value.strip()
            # TODO: If self.fmt is None, we infer a suitable format which doesn't discard any
            # information using the first value we see. This works well in practice because we only
            # ever see a single value, but if we were performing multiple queries we *might* infer
            # an over-restrictive format. This probably wouldn't happen because the router seems to
            # return floating point values with decimal places even if they are all zero.
            if self.fmt is None:
                decimal_point = string_value.rfind(".")
                if decimal_point == -1:
                    self.fmt = "%d"
                else:
                    decimal_places = len(string_value) - (decimal_point + 1)
                    self.fmt = "%%.%df" % decimal_places
            return float(string_value) / self.divisor
        except ValueError as e:
            self.log_parse_error(string_value, e)
            return None


class HexStatistic(SimpleStatistic):
    def __init__(self, router_key, desc, fmt="%d", divisor=1.0, hide=False, csv_key=None):
        SimpleStatistic.__init__(self, router_key, desc, fmt, hide, csv_key)
        self.divisor = divisor

    def parse_router_value(self, string_value):
        if string_value == "":
            return None
        try:
            return int(string_value, 16) / self.divisor
        except ValueError as e:
            self.log_parse_error(string_value, e)
            return None


class DerivedStatistic(Statistic):
    def __init__(self, csv_key, router_keys, desc, fn, hide=False):
        Statistic.__init__(self, csv_key, router_keys, desc, hide)
        self.fn = fn

    def csv_str(self, simple_statistics):
        # We could just pass simple_statistics through as the second argument here, but to keep
        # code honest we only pass through the keys in self.router_keys, i.e. the keys this
        # statistic said it depends on.
        return self.fn(self,
                       {k: v for (k, v) in simple_statistics.items() if k in self.router_keys})


def get_parsed_router_values(session, statistic_list):
    router_keys = set(itertools.chain.from_iterable(
        statistic.router_keys for statistic in statistic_list if not statistic.hide))
    raw_router_values = get_raw_router_values(session, router_keys)
    parsed_router_values = {}
    single_router_keys = set()
    for statistic in statistic_list:
        if len(statistic.router_keys) == 1:
            router_key = statistic.router_keys[0]
            if router_key in single_router_keys:
                die("Router key '%s' is used by more than one simple statistic" % router_key)
            single_router_keys.add(router_key)
            parsed_router_values[router_key] = \
                statistic.parse_router_value(raw_router_values.get(router_key, ""))

    # Validate that there are no statistics which depend on router keys we didn't fetch; if this
    # happens it implies some problem with the declared dependencies or the logic to generate the
    # set of router keys to fetch. TODO: This doesn't exactly belong here, but it's a convenient
    # place to check.
    for statistic in statistic_list:
        if len(statistic.router_keys) > 1:
            statistic_router_keys = set(statistic.router_keys)
            missing_router_keys = statistic_router_keys - single_router_keys
            if len(missing_router_keys) > 0:
                die("Statistic '%s' depends on router keys which are not fetched: %s"
                    % (statistic.csv_key, ",".join(missing_router_keys)))

    return parsed_router_values


def get_csv_row(session, statistic_list):
    result = []
    for statistic in statistic_list:
        if not statistic.hide:
            result.append(statistic.csv_str(simple_statistics))
    return result


def derive_4g_connected_band(self, simple_statistics):
    def format_helper(bandwidth, band):
        # TODO: I'm not sure how the router web interface would handle the ones
        # with suffixes like SDL, but this will do for now.
        band_frequency = {
            "20": "800",
             "8": "900",
            "32": "1400SDL",
             "3": "1800",
             "1": "2100",
            "40": "2300",
             "7": "2600FDD",
            "38": "2600TDD",
            "42": "3400"
        }.get(band, "???")
        return "%sMHz@%s(B%s)" % (bandwidth, band_frequency, band)

    def get_helper(key, fmt):
        value = simple_statistics.get(key)
        return None if value is None else fmt % value

    result = ""

    primary_bandwidth = get_helper("lte_ca_pcell_bandwidth", "%.1f")
    primary_band = get_helper("lte_ca_pcell_band", "%d")
    if primary_band is not None and primary_bandwidth is not None:
        result += format_helper(primary_bandwidth, primary_band)

    # TODO: I don't know if we can have a secondary without a primary; if we do, we'll
    # semi-deliberately indicate that via a mangled format starting with a "+".
    secondary_bandwidth = get_helper("lte_ca_scell_bandwidth", "%.1f")
    secondary_band = get_helper("lte_ca_scell_band", "%d")
    if secondary_band is not None and secondary_bandwidth is not None:
        result += " + " + format_helper(secondary_bandwidth, secondary_band)

    return result


def get_test_download_values():
    # We always log the URL to indicate we attempted a download; lack of any associated statistics
    # in the CSV output will show that it failed.
    result = {"test_download_url": test_download_url}
    try:
        # Note that we don't use session here - this is a download from a real web site, not the
        # router.
        test_download_start = time.time()
        test_download_response = requests.get(test_download_url)
        test_download_end = time.time()
        test_download_response.raise_for_status()
        test_download_size = len(test_download_response.content)
        test_download_time = max(test_download_end - test_download_start, 0.001)
        result["test_download_size_mb"] = test_download_size / megabyte
        result["test_download_time"] = test_download_time
        result["test_download_rate"] = (test_download_size / megabyte) / test_download_time
    except requests.exceptions.RequestException as e:
        log_exception(e)
    return result


# In order to keep verbosity down, statistics_list has two overlapping functions:
# - it defines the columns of the CSV file, in order (all statistics except ones with hide=True)
# - it defines how to parse parameters returned by the router API; these may be used by derived
#   statistics even if they are hidden.
#
# It would probably be more elegant to have:
# - a list of router keys, indicating how each should be parsed
# - a list of derived CSV keys, indicating how each should be derived from the router keys
# - a list of (router keys|derived CSV keys), indicating what goes into the CSV file and in what
#   order
# However, this would mean duplicating the somewhat unfriendly keys in multiple places.
statistics_list = [
    DerivedStatistic("timestamp_utc", [], "Timestamp (UTC)",
                     lambda self, _: datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),

    DecimalStatistic("rmcc", "Mobile Carrier Code"),
    DecimalStatistic("rmnc", "Mobile Network Code"),
    StringStatistic("network_provider", "Network"),
    StringStatistic("imei", "IMEI"),
    StringStatistic("sim_imsi", "IMSI"),
    StringStatistic("wa_inner_version", "Software Version"),
    StringStatistic("wan_lte_ca", "CA Status"), # TODO: plausible guess, I have never seen CA on

    # Using %.6f here provides kilobyte resolution.
    DecimalStatistic("monthly_tx_bytes", "Monthly Data Tx (GB)", csv_key="monthly_tx_gb",
                     divisor=gigabyte, fmt="%.6f"),
    DecimalStatistic("monthly_rx_bytes", "Monthly Data Rx (GB)", csv_key="monthly_rx_gb",
                     divisor=gigabyte, fmt="%.6f"),
    DecimalStatistic("realtime_time", "Connection Uptime (s)"),

    # Network Information (4G)
    DecimalStatistic("wan_active_channel", "4G Frequency"),
    DerivedStatistic(
        "4g_connected_band",
        [
            "lte_ca_pcell_band", "lte_ca_pcell_bandwidth", "lte_ca_scell_band",
            "lte_ca_scell_bandwidth"
        ],
        "4G Connected Band", derive_4g_connected_band),
    DecimalStatistic("lte_ca_pcell_band", "4G Connected Band, Primary"),
    DecimalStatistic("lte_ca_pcell_bandwidth", "4G Connected Band, Primary Bandwidth (MHz)"),
    DecimalStatistic("lte_ca_scell_band", "4G Connected Band, Secondary"),
    DecimalStatistic("lte_ca_scell_bandwidth", "4G Connected Band, Secondary Bandwidth (MHz)"),
    DecimalStatistic("lte_rsrp", "4G Signal Strength (dBm)"),
    DecimalStatistic("lte_snr", "4G ECIO/SINR (dB)"),
    HexStatistic("lte_pci", "4G PCI"),
    HexStatistic("cell_id", "4G Cell ID"),

    # Network Information (5G)
    DecimalStatistic("nr5g_action_channel", "5G Frequency"),
    StringStatistic("nr5g_action_band", "5G Connected Band"),
    DecimalStatistic("Z5g_rsrp", "5G Signal Strength (dBm)"),
    DecimalStatistic("Z5g_SINR", "5G SINR (dB)"),
    HexStatistic("nr5g_pci", "5G PCI"),
    # TODO: Z5g_CELL_ID is always empty and the corresponding item shown in the router web GUI seems
    # to be empty too. Get rid of this or comment it out?
    DecimalStatistic("Z5g_CELL_ID", "5G (SA) Cell ID"),

    # TODO: Due to the slightly inelegant way the test download statistics are handled, divisor
    # other than 1 and auto-derivation of fmt doesn't work here. It's probably cleaner without them,
    # but this is a bit of wart.
    StringStatistic("test_download_url", "Test Download URL"),
    DecimalStatistic("test_download_size_mb", "Test Download Size (MB)", fmt="%.3f"),
    DecimalStatistic("test_download_time", "Test Download Time (s)", fmt="%.2f"),
    # TODO: We could implement the download rate as a DerivedStatistic, but it's probably more
    # trouble than it's worth - we'd need to declare its dependency on the above statistics, but
    # avoid trying to fetch them from the router.
    DecimalStatistic("test_download_rate", "Test Download Rate (MB/s)", fmt="%.3f"),
]

for csv_key in config.suppressed_csv_keys:
    found = False
    for statistic in statistics_list:
        if statistic.csv_key.lower() == csv_key.lower():
            statistic.hide = True
            found = True
            break
    if not found:
        die("Unrecognised suppressed column: %s" % csv_key)



# === CSV file handling


# CsvUpdater is designed to allow "safe" updating of CSV files with this structure:
#     time,   foo,                bar,            baz,            quux
#     Time,   Foos per minute,    Bar quotient,   Wowrbazzles,    Quuxulations
#     00:02,  3,                  1,              2,              9
#     00:15,  12.3,               4,              ,               5
#     ...,    ...,                ...,            ...,            ...
#
# In other words, the first row consists of a set of keys, the second row consists of a set of
# human-readable descriptions for those keys and subsequent rows contain data associated with those
# keys.
#
# If the set of keys never changes everything is trivial. If it does, we don't want to discard old
# data. This class regenerates the file so that the current keys appear first in the specified
# order, but any keys which appear only in the old data (called "deprecated keys") get moved into
# columns to the right of all the current keys. This keeps them out of the way to some extent
# without losing data. A user can choose to explicitly delete these columns using a CSV editor and
# they will then no longer appear.
#
# The entire file is read in and written back out each time. This is done via a temporary file which
# is atomically renamed over the input file right at the end. This is inefficient but does avoid any
# risk of a partial row being written (if we did nothing but append, ignoring the problem of
# changing the set of keys) or losing data because of a crash part-way through writing the data back
# out (if we regenerated the file in place).
class CsvUpdater:
    def __init__(self, csvfile, new_keys, new_descs):
        self.csvfile = csvfile
        self.new_keys = list(new_keys)
        self.new_descs = list(new_descs)
        self.deprecated_keys = []
        self.deprecated_descs = []
        self.data = []
        self.have_existing_file = False

        try:
            old_column_index_for_key = {}
            with open(csvfile, "r") as f:
                self.have_existing_file = True
                csvreader = csv.reader(f)
                csvreader_iter = csvreader.__iter__()

                # Determine the old keys from the first line of the file. The second line of the
                # file is assumed to contain human-readable descriptions corresponding to those
                # keys.
                old_key_row = csvreader_iter.__next__()
                old_desc_row = csvreader_iter.__next__()
                for old_column_index, (old_key, old_desc) in \
                        enumerate(itertools.zip_longest(old_key_row, old_desc_row, fillvalue="")):
                    if old_key in old_column_index_for_key:
                        die("Duplicate key '%s' found in existing CSV file" % old_key)
                    old_column_index_for_key[old_key] = old_column_index
                    if old_key not in self.new_keys:
                        self.deprecated_keys.append(old_key)
                        self.deprecated_descs.append(old_desc)

                # Loop over the data rows making up the rest of the input, transforming them so they
                # follow the desired output column order of new_keys + deprecated_keys.
                for old_data_row in csvreader_iter:
                    data_row = []
                    for key in self.new_keys + self.deprecated_keys:
                        old_col = old_column_index_for_key.get(key)
                        if old_col is not None:
                            data_row.append(old_data_row[old_col])
                        else:
                            data_row.append("")
                    self.data.append(data_row)
        except (FileNotFoundError, StopIteration):
            pass

    def writerow(self, new_row):
        assert len(new_row) == len(self.new_keys)
        self.data.append(new_row + [""] * len(self.deprecated_keys))

    def save(self, tempfile):
        with open(tempfile, "w") as f:
            csvwriter = csv.writer(f)
            csvwriter.writerow(self.new_keys + self.deprecated_keys)
            csvwriter.writerow(self.new_descs + self.deprecated_descs)
            for row in self.data:
                assert len(row) == len(self.new_keys) + len(self.deprecated_keys)
                csvwriter.writerow(row)

        # TODO: This check is not entirely correct - shrinking the human-readable descriptions could
        # cause the new file to be legitimately smaller than the old file. In practice this won't
        # happen and at least until this code has been more thoroughly tested this feels like a nice
        # safety check.
        if self.have_existing_file and os.path.getsize(tempfile) < os.path.getsize(self.csvfile):
            die("New CSV file is smaller than old CSV file - will not replace it")

        # This rename should be atomic.
        os.rename(tempfile, self.csvfile)


# === Top-level control logic


try:
    # Actually get the statistics from the router.
    session = start_session(config.router_address, config.router_username, config.router_password,
                            cmd_args.polite)
    simple_statistics = get_parsed_router_values(session, statistics_list)

    # Do any test download after obtaining the other data correctly, so if that fails for some
    # reason we don't waste time and bandwidth.
    if cmd_args.download:
        simple_statistics.update(get_test_download_values())

    # Record the statistics in the CSV file.
    csv_updater = CsvUpdater(
        config.csv_file,
        (statistic.csv_key for statistic in statistics_list if not statistic.hide),
        (statistic.desc for statistic in statistics_list if not statistic.hide))
    csv_updater.writerow(get_csv_row(simple_statistics, statistics_list))
    csv_updater.save(config.temp_csv_file)
except RuntimeError as e:
    die(str(e))


# TODO: Would it be worth recording the host's ethernet tx/rx bytes? These are obviously not
# identical to the broadband data use, but with a single machine constituting the bulk of the
# internet access they should correlate and this would help to validate that the router is tracking
# data use correctly. To be fair, I'd expect the router to get this right given users will rely on
# it to avoid going over their data allowance, but it might be interesting to have something to
# cross-reference the router stats with.
