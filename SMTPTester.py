# Python 3 script to test SMTP server for spoofing vulnerabilities
# made by @x_Freed0m

import sys
import argparse
import logging
from colorlog import ColoredFormatter
import os.path
from smtplib import SMTP, SMTPRecipientsRefused, SMTPSenderRefused
from email.mime.text import MIMEText


def args_parse():
    data = "This email is part of a security testing approved by the Security department. Thank " \
           "you for your cooperation, Please forward this email to \n"
    args_parser = argparse.ArgumentParser()
    args_parser.add_argument('--targets', help="SMTP target server address or file containing "
                                               "SMTP servers list", required=True)
    args_parser.add_argument('-p', '--port', help="SMTP target server port to use (default is 25)",
                             type=int, default=25)
    args_parser.add_argument('--tester', help="Pentester email address", required=True)
    args_parser.add_argument('-t', '--toaddr', help="The recipient address (To)")
    args_parser.add_argument('-f', '--fromaddr', help="the sender address (From)")
    args_parser.add_argument('-d', '--data', help="The email content (data)", default=data)
    args_parser.add_argument('-a', '--address', help="Addresses to use with VRFY, can be single "
                                                     "or a file")
    args_parser.add_argument('-s', '--subject', help="the Subject to use in the email, default is "
                                                     '"SMTP Pentest"', default="SMTP server "
                                                                               "Pentest")
    args_parser.add_argument('-i', '--internal',
                             help="Perform internal spoofing test. ", action="store_true")
    args_parser.add_argument('-e', '--external', help="Perform external relay test. ",
                             action="store_true")
    args_parser.add_argument('-v', '--vrfy', help="Perform user enumeration using the VRFY command",
                             action="store_true")
    args_parser.add_argument('--debug', help="debug mode switch - to print all the server "
                                             "commands and output to stdout", action="store_true")
    return args_parser.parse_args()


def configure_logger():
    """
        This function is responsible to configure logging object.
    """

    global LOGGER
    LOGGER = logging.getLogger("SMTPTester")
    # Set logging level
    LOGGER.setLevel(logging.INFO)

    # Create console handler
    log_colors = {
        'DEBUG': 'bold_red',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red',
    }
    formatter = "%(log_color)s[%(asctime)s] - %(message)s%(reset)s"
    formatter = ColoredFormatter(formatter, datefmt='%d-%m-%Y %H:%M', log_colors=log_colors)
    ch = logging.StreamHandler(sys.stdout)  # Handler to print the logs to stdout
    ch.setFormatter(formatter)
    LOGGER.addHandler(ch)
    fh = logging.FileHandler("SMTPTester.log")  # Handler to print the logs to a file in append mode
    fh.setFormatter(formatter)
    LOGGER.addHandler(fh)


def excptn(e):
    LOGGER.critical("[!] Exception: " + str(e))
    exit(1)


def banner():
    print("""
     #####  #     # ####### ######  #######                                   
    #     # ##   ##    #    #     #    #    ######  ####  ##### ###### #####  
    #       # # # #    #    #     #    #    #      #        #   #      #    # 
     #####  #  #  #    #    ######     #    #####   ####    #   #####  #    # 
          # #     #    #    #          #    #           #   #   #      #####  
    #     # #     #    #    #          #    #      #    #   #   #      #   #  
     #####  #     #    #    #          #    ######  ####    #   ###### #    #
    \nMade by @x_Freed0m
    """)


def external_test(smtp_targets, port, fromaddr, recipient, data, subject, debug):
    for target in smtp_targets:
        LOGGER.info("[*] Checking host " + target + ':' + str(port))
        LOGGER.info("[*] Testing for mail relaying (external)")
        try:
            if fromaddr and recipient:  # checking we have both to and from addresses
                with SMTP(target, port) as current_target:
                    if debug:
                        current_target.set_debuglevel(1)
                    current_target.ehlo_or_helo_if_needed()
                    msg = MIMEText(data)
                    msg['Subject'] = subject
                    msg['From'] = fromaddr
                    msg['To'] = recipient

                    current_target.sendmail(fromaddr, recipient, msg.as_string())
                    LOGGER.info("[+] Server %s Appears to be vulnerable for external relay! email "
                                "send FROM: %s TO: %s", target, fromaddr, recipient)
            else:
                LOGGER.critical("[!] Problem with FROM and/or TO address!")
                exit(1)
        except (SMTPRecipientsRefused, SMTPSenderRefused) as e:
            LOGGER.critical("[!] SMTP Error: %s\n[-] Server: %s NOT vulnerable!", str(e), target)
        except ConnectionRefusedError:
            LOGGER.critical("[!] Connection refused by host %s", target)
        except KeyboardInterrupt:
            LOGGER.critical("[!] [CTRL+C] Stopping...")
            exit(1)
        except Exception as e:
            excptn(e)


def internal_test(smtp_targets, port, fromaddr, toaddr, data, subject, debug):
    for target in smtp_targets:
        LOGGER.info("[*] Checking host %s:%s for internal spoofing", target, str(port))
        try:
            if fromaddr and toaddr:  # making sure we have both from and to addresses
                from_domain = fromaddr.split('@').pop()  # getting the domain name from the address
                to_domain = toaddr.split('@').pop()  # getting the domain name from the address
                if from_domain != to_domain:  # making sure the spoofing is for the same domain
                    # otherwise it's relay and not spoofing
                    LOGGER.error("[!] Sender and recipient domains doesn't match!")
                else:
                    with SMTP(target, port) as current_target:
                        if debug:
                            current_target.set_debuglevel(1)
                        current_target.ehlo_or_helo_if_needed()
                        msg = MIMEText(data)
                        fromaddr = fromaddr
                        toaddr = toaddr
                        msg['Subject'] = subject
                        msg['From'] = fromaddr
                        msg['To'] = toaddr

                        current_target.sendmail(fromaddr, toaddr, msg.as_string())
                        LOGGER.info("[+] Server %s Appears to be vulnerable for internal "
                                    "spoofing! Used FROM: %s", target, fromaddr)
            else:
                LOGGER.critical("[!] Problem with FROM and/or TO address!")
                exit(1)
        except (SMTPRecipientsRefused, SMTPSenderRefused) as e:
            LOGGER.critical("[!] SMTP Error: %s\n[-] Server: %s NOT vulnerable or TO address "
                            "doesn't exist!", str(e), target)
        except ConnectionRefusedError:
            LOGGER.critical("[!] Connection refused by host %s", target)
        except KeyboardInterrupt:
            LOGGER.critical("[CTRL+C] Stopping...")
            exit(1)
        except Exception as e:
            excptn(e)


def vrfy(smtp_targets, port, vrfy_addresses, debug):
    for target in smtp_targets:
        LOGGER.info("[*] Checking host %s:%s for username enumeration using VRFY", target,
                    str(port))
        try:
            with SMTP(target, port) as current_target:
                for tested_address in vrfy_addresses:
                    if debug:
                        current_target.set_debuglevel(1)
                    current_target.ehlo_or_helo_if_needed()
                    attempt = current_target.verify(tested_address)
                    # Taken from here: https://www.greenend.org.uk/rjk/tech/smtpreplies.html
                    # VRFY
                    # 250 Requested mail action okay, completed
                    # 251 User not local; will forward to <forward-path>
                    # 252 Cannot VRFY user, but will accept message and attempt delivery
                    # 550 Requested action not taken: mailbox unavailable
                    # 551 User not local; please try <forward-path>
                    # 553 Requested action not taken: mailbox name not allowed
                    # 500 Syntax error, command unrecognised
                    # 501 Syntax error in parameters or arguments
                    # 502 Command not implemented
                    # 504 Command parameter not implemented
                    # 421 <domain> Service not available, closing transmission channel
                    # 550 Requested action not taken: mailbox unavailable
                    # r is a tuple, with (r_code, r_msg).
                    # r[0] is the replay code
                    # domain = vrfy_addresses.split('@').pop()
                    if attempt[0] in [250, 252]:
                        LOGGER.info("[+] VRFY Success for address: %s on server: %s",
                                    tested_address, target)
                    else:
                        LOGGER.error("[!] VRFY failed for %s on server: %s", tested_address,
                                     target)

        except KeyboardInterrupt:
            LOGGER.critical("[!] [CTRL+C] Stopping...")
            exit(1)
        except Exception as e:
            excptn(e)


def main():
    args = args_parse()
    configure_logger()
    banner()
    data = args.data + args.tester  # adding the pentest email to the content of the email sent
    fake_address = "FakeDoNotExist@pentesting.pentesting"
    if os.path.exists(args.targets):  # checking if the switch is single entry or a file
        smtp_targets = open(args.targets).read().splitlines()
    else:
        smtp_targets = [args.targets]
    if args.external:
        external_test(smtp_targets, args.port, args.fromaddr, args.tester, data, args.subject,
                      args.debug)
        external_test(smtp_targets, args.port, fake_address, args.tester, data, args.subject,
                      args.debug)
    elif args.internal:
        internal_test(smtp_targets, args.port, args.fromaddr, args.toaddr, data, args.subject,
                      args.debug)
    elif args.vrfy:
        if not args.address:
            LOGGER.critical("[!] Missing the address switch")
        elif os.path.exists(args.address):  # checking if the switch is single entry or a file
            vrfy_addresses = open(args.address).read().splitlines()
            vrfy(smtp_targets, args.port, vrfy_addresses, args.debug)
        else:
            vrfy_addresses = [args.address]
            vrfy(smtp_targets, args.port, vrfy_addresses, args.debug)
    else:
        external_test(smtp_targets, args.port, args.fromaddr, args.tester, data, args.subject,
                      args.debug)
        external_test(smtp_targets, args.port, fake_address, args.tester, data, args.subject,
                      args.debug)
        internal_test(smtp_targets, args.port, args.fromaddr, args.toaddr, data, args.subject,
                      args.debug)


if __name__ == '__main__':
    main()
