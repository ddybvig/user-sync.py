import sys
import argparse
import config
import auth_store
import csv
import logging
import input
import connector
from umapi import UMAPI
from umapi.auth import Auth
from umapi.helper import paginate


def process_args():
    parser = argparse.ArgumentParser(description='Adobe Enterprise Dashboard User Management Connector')
    parser.add_argument('-l', '--ldap-config', dest='ldap_config', default=None,
                        help='LDAP Config Path - if not provided, tries to get input from file or stdin')
    parser.add_argument('-i', '--infile', dest='infile', default=None,
                        help='input file - reads from stdin if this parameter is omitted')
    parser.add_argument('-V', '--version',
                        action='version',
                        version='%(prog)s (version 0.5.0)')

    req_named = parser.add_argument_group('required arguments')
    req_named.add_argument('-c', '--config', dest='config_path', required=True,
                           help='API Config Path')
    req_named.add_argument('-g', '--group-config', dest='group_config', required=True,
                           help='Group Config Path')
    req_named.add_argument('-a', '--auth-store', dest='auth_store_path', required=True,
                           help='Auth Store Path')

    return parser.parse_args()


def init_log():
    logging.basicConfig(format='%(asctime)s\t%(levelname)s\t%(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        level=logging.DEBUG)


def main():
    # init the log
    init_log()

    # process command line args
    args = process_args()

    # initialize configurator
    c = config.init(open(args.config_path, 'r'))
    store = auth_store.init(c, args.auth_store_path)
    token = store.token()
    auth = Auth(c['enterprise']['api_key'], token)

    api = UMAPI("https://" + c['server']['host'] + c['server']['endpoint'], auth)

    if args.ldap_config:
        logging.info('Found LDAP config -- %s', args.ldap_config)
        lc = config.ldap_config(open(args.ldap_config, 'r'))
        directory_users = input.from_ldap(lc['host'], lc['username'], lc['pw'], c['enterprise']['domain'])
    else:
        logging.info('LDAP config not provided')
        if args.infile:
            logging.info('Found input file -- %s', args.infile)
            infile = open(args.infile, 'r')
        else:
            logging.info('No input file - reading stdin')
            infile = sys.stdin

        directory_users = input.from_csv(csv.DictReader(infile, delimiter='\t'))

    group_config = dict([(g['directory_group'], g['dashboard_groups'])
                         for g in config.group_config(open(args.group_config, 'r'))])

    logging.info('Group config initialized')

    adobe_users = dict([(u['email'], u) for u in paginate(api.users, c['enterprise']['org_id'])])

    logging.info('Retrieved Adobe users')

    connector.process_rules(api, c['enterprise']['org_id'], directory_users, adobe_users, group_config)

    logging.info('Finished processing')

if __name__ == '__main__':
    main()
