import paramiko
import csv
import re
import os
import logging
import socket
import pandas


# Function to stablish SSH session to device and execute a command or set of commands received from the main function
def connect_to_device(ip_address, username, password, command_to_run):
    print("\n------------------------------------------------------")
    print("--- Attempting paramiko connection to: ", ip_address)

    try:
        # Create paramiko session
        ssh_client = paramiko.SSHClient()

        # Must set missing host key policy since we don't have the SSH key stored in the 'known_hosts' file
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Make the connection to our host.
        ssh_client.connect(hostname=ip_address,
                           username=username,
                           password=password)

        # If there is an issue, paramiko will throw an exception, so the SSH request must have succeeded.
        print("--- Success! connecting to: ", ip_address)
    except paramiko.AuthenticationException:
        logger.debug("Authentication failed, please verify your credentials: %s")
    except socket.error as strerror:
        logger.debug("TCP Error connection: %s" % strerror)
    except paramiko.SSHException as strerror:
        logger.debug("Unable to establish SSH connection: %s" + strerror)

    try:
        # Runs the command received from the function call
        stdin, stdout, stderr = ssh_client.exec_command(command_to_run)
        command_result = stdout.readlines()
    except paramiko.SSHException as strerror:
        logger.debug("SSH Error - %s " + strerror)

    # Returns the output of the command received
    return command_result


def main():
    # Read list of ips to connect from CSV file and skips the first row
    logger.debug("Getting list of devices from CSV File")
    host_list = open(r"C:\Users\jjimenez\Documents\GitHub\Cisco\Devices.csv", "rt")
    read_file = csv.reader(host_list)
    next(read_file)

    counter = 1
    device_dictionary = {}
    current_path = os.getcwd()

    # Loops the content of the of the CSV file and performs the operations "show run" and "show version"
    for row in read_file:
        row_str = ' '.join(row)

        # Get hostname from list and leave only the name from the list
        logger.debug("Connecting to Device " + row_str + "to get hostname")
        hostname = connect_to_device(row_str, "crgadmin", "CRG3mpow3rs@dm1n", "show run | inc hostname")

        for hn in hostname:
            if "hostname" in hn:
                str_hostname = hn
                break

        logger.debug("Device hostname = " + str_hostname)
        str_hostname = str_hostname[9:-2]
        dir_name = str_hostname
        str_hostname = str_hostname.rstrip() + ".txt"

        # To get the output of show run and save to a file
        logger.debug("Connecting to Device " + row_str + "to get output of show run")
        show_run_output = connect_to_device(row_str, "crgadmin", "CRG3mpow3rs@dm1n", "sh run")
        os.mkdir(current_path + "\\outputs\\Devices\\" + dir_name)
        os.mkdir(current_path + "\\outputs\\Devices\\" + dir_name + "\\run")
        file_path = current_path + "\\outputs\\Devices\\" + dir_name + "\\run\\sh_run_" + str_hostname
        try:
            my_output_file = open(file_path, "w")
            my_output_file.writelines(show_run_output)
            my_output_file.close()
            logger.debug("Writing show run to txt file")
        except IOError as strerror:
            logger.debug("Error creating File %s " + strerror)

        # To get the output of show version and save to a file
        logger.debug("Connecting to Device " + row_str + "to get output of show version")
        show_ver_output = connect_to_device(row_str, "crgadmin", "CRG3mpow3rs@dm1n", "sh version")
        os.mkdir(current_path + "\\outputs\\Devices\\" + dir_name + "\\version")
        file_path = current_path + "\\outputs\\Devices\\" + dir_name + "\\version\\sh_ver_" + str_hostname
        try:
            my_output_file = open(file_path, "w")
            my_output_file.writelines(show_ver_output)
            my_output_file.close()
        except IOError as strerror:
            logger.debug("Error creating File %s " + strerror)

        # Get the IOS version from the show run
        logger.debug("Converting output of show version to string to find IOS version on the string")
        show_ver_str = ' '.join(show_ver_output)
        version_pattern = re.compile("Version ([0-9]*\.[0-9][\(\)0-9a-zA-Z]*)")
        device_ios_version = re.search(version_pattern, show_ver_str).group(1)

        # Write information to different arrays so then it can be written into a CSV file
        logger.debug("Writing device hostname, IP and IOS to a Python Directory")
        str_hostname = str_hostname[:-4]
        str_counter = str(counter)
        str_ip = ' '.join(row)
        device_dictionary[str_counter] = {"hostname": str_hostname, "IP": str_ip, "IOS": device_ios_version}
        counter = counter + 1

    # To write hostname,ip,ios to a CSV file for audit/report
    logger.debug("About to python directory containing device information to csv file")
    csv_file = current_path + "\\outputs\\Device_Info.csv"
    try:
       pandas.DataFrame.from_dict(device_dictionary,orient="index").to_csv(csv_file)
    except csv.Error as strerror:
        logger.debug("Error creating File %s " + strerror)


if __name__ == '__main__':
    # Setting up loggin
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)

    handler = logging.FileHandler('process.log')
    handler.setLevel(logging.DEBUG)

    # create a logging format
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    # add the handlers to the logger
    logger.addHandler(handler)
    main()
