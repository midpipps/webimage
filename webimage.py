'''
Scan an ip range for web servers and gets the data from it
'''
import sys
import datetime
import argparse
import subprocess
import json
import os
import zipfile
import shutil
import html
import urllib3
import requests
from netaddr import IPNetwork, AddrFormatError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
VERSION = '0.2'
PROGRAM_NAME = 'Web Image Scanner'
TIMEOUTS = (3.05, 20) #connect timeout, read timeout


class Output(object):
    '''
    class handles the output from the scanner
    '''
    def __init__(self, command, stdout=None, xmlout=None, jsonout=None, search=None):
        self._command = command
        self._stdout = stdout
        self._xmlout = xmlout
        self._jsonout = jsonout
        self._firstout = True
        self._search = search
        self._open()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _open(self):
        '''
        open all the file handlers for writing output
        '''
        if self._stdout:
            self._stdout = open(self._stdout, 'w')
        if self._xmlout:
            self._xmlout = open(self._xmlout, 'w')
        if self._jsonout:
            self._jsonout = open(self._jsonout, 'w')
        self._startoutput()

    def _searchresponse(self, responsetext):
        '''
        Searches the responsetext for the terms in the search
        '''
        #TODO need to update this to accept more seach terms
        if self._search and self._search in responsetext:
            return self._search
        return None
    def _startoutput(self):
        '''
        start the output off
        '''
        outputlist = [PROGRAM_NAME, VERSION, datetime.datetime.now().isoformat(), self._command.replace('"', '')]
        print("Starting {0}\nVersion:{1}\nStartTime:{2}\nCommand:{3}\n".format(*outputlist))
        if self._stdout:
            self._stdout.write("Starting {0}\nVersion:{1}\nStartTime:{2}\nCommand:{3}\n".format(*outputlist))
        if self._xmlout:
            self._xmlout.write('<webscan>\n')
            self._xmlout.write('<scaninfostart programname="{0}" starttime="{2}" version="{1}" command="{3}"/>\n'.format(*outputlist))
            self._xmlout.write('<scans>\n')
        if self._jsonout:
            self._jsonout.write('{"webscan":{')
            self._jsonout.write('"scaninfostart":{{"starttime":"{2}", "version":"{1}", "command":"{3}", "programname":"{0}"}}'.format(*outputlist))
            self._jsonout.write(',"scans":[')

    def _endoutput(self):
        '''
        end the output
        '''
        outputlist = [PROGRAM_NAME, datetime.datetime.now().isoformat()]
        if self._stdout:
            self._stdout.write("{0} EndTime:{1}".format(*outputlist))
        if self._xmlout:
            self._xmlout.write('</scans>\n')
            self._xmlout.write('<scaninfoend endtime="{1}"/>\n'.format(*outputlist))
            self._xmlout.write('</webscan>\n')
        if self._jsonout:
            self._jsonout.write(']')
            self._jsonout.write(',"scaninfoend":{{"endtime":"{1}"}}'.format(*outputlist))
            self._jsonout.write('}}')

    def _ipresponse(self, response):
        '''
        output the start of the scan including the ip address
        '''
        print("IPaddress: {0}\n".format(response[0]))
        if self._stdout:
            self._stdout.write("IPaddress:{0}\n".format(response[0]))
        if self._xmlout:
            self._xmlout.write('<scan ipaddress="{0}">\n<ports>'.format(response[0]))
        if self._jsonout:
            if self._firstout:
                self._firstout = False
            else:
                self._jsonout.write(',')
            self._jsonout.write('{{"ipaddress":"{0}","ports":['.format(response[0]))

    def _portresponse(self, response):
        '''
        Output the port responses to the appropriate places
        '''
        firstport = True
        for port, resp in response[1].items():
            #loop over the ports and output the information
            #TODO fix encoding to be more appropriate
            if resp:
                searchresponse = self._searchresponse(resp.text)
                print("\tPORT:{0}\n".format(port))
                print("\t\tStatusCode:{0}\n".format(resp.status_code))
                print("\t\tText:{0}\n".format(resp.text.encode('UTF-8', 'ignore')))
                if searchresponse:
                    print("\t\tSearch Hits:{0}\n".format(searchresponse))
                if self._stdout:
                    self._stdout.write("\tPort:{0}\n".format(port))
                    self._stdout.write("\t\tStatusCode:{0}\n".format(resp.status_code))
                    self._stdout.write("\t\tText:{0}\n".format(resp.text.encode('UTF-8', 'ignore')))
                    if searchresponse:
                        self._stdout.write("\t\tSearch Hits:{0}\n".format(searchresponse))
                if self._xmlout:
                    self._xmlout.write('<port number="{0}" status_code="{1}">\n'.format(port, resp.status_code))
                    if searchresponse:
                        self._xmlout.write('<search hits="{0}" />\n'.format(searchresponse))
                    self._xmlout.write('<text>\n')
                    self._xmlout.write(html.escape('{0}'.format(resp.text.encode('UTF-8', 'ignore'))))
                    self._xmlout.write('</text>\n')
                    self._xmlout.write('</port>\n')
                if self._jsonout:
                    if firstport:
                        firstport = False
                    else:
                        self._jsonout.write(',')
                    self._jsonout.write('{{"port":{0}'.format(port))
                    self._jsonout.write(',"status_code":"{0}"'.format(resp.status_code))
                    self._jsonout.write(',"text":{0}'.format(json.dumps(resp.text)))
                    if searchresponse:
                        self._jsonout.write(',"searchhits":"{0}"'.format(searchresponse))
                    self._jsonout.write('}')

    def _endresponse(self):
        '''
        output the end of the response object
        '''
        print("\n\n")
        if self._stdout:
            self._stdout.write("\n\n")
        if self._xmlout:
            self._xmlout.write('</ports></scan>\n')
        if self._jsonout:
            self._jsonout.write(']}')

    def addresponsedata(self, response):
        '''
        Output the response data
        '''
        self._ipresponse(response)
        self._portresponse(response)
        self._endresponse()

    def close(self):
        '''
        close out all the file handlers
        '''
        self._endoutput()
        if self._stdout:
            self._stdout.close()
        if self._xmlout:
            self._xmlout.close()
        if self._jsonout:
            self._jsonout.close()

def httporhttps(address, port, request_session):
    '''
    figure out if the address is https or http
    '''
    finalprotocol = None
    finalurl = None
    connrefused = False
    try:
        connected_web = "https://{0}:{1}".format(address, port)
        with request_session.head(connected_web, timeout=TIMEOUTS) as response:
            resp_dat = response
            if resp_dat and resp_dat.status_code == 200:
                if 'https' in resp_dat.url:
                    finalprotocol = "https://"
                    finalurl = resp_dat.url
    except ConnectionRefusedError:
        finalprotocol = None
        connrefused = True
    except requests.ConnectionError:
        finalprotocol = None
    except requests.ReadTimeout:
        finalprotocol = None

    if not finalprotocol and not connrefused:
        #well https did not work need to try again
        try:
            connected_web = "http://{0}:{1}".format(address, port)
            with request_session.head(connected_web, timeout=TIMEOUTS) as response:
                resp_dat = response
                if resp_dat and resp_dat.status_code == 200:
                    finalprotocol = "http://"
                    finalurl = resp_dat.url
        except ConnectionRefusedError:
            finalprotocol = None
        except requests.ConnectionError:
            finalprotocol = None
        except requests.ReadTimeout:
            finalprotocol = None
    return finalprotocol, finalurl

def ipparse(values):
    '''
    parse a list of ips/cidr into a list of ip addresses
    '''
    if values:
        iplist = list()
        #comma seperated list of ips need to split and parse
        for tempip in values.split(','):
            try:
                for net in IPNetwork(tempip.strip()):
                    iplist.append(net)
            except ValueError:
                iplist = None
            except AddrFormatError:
                iplist = None

        if iplist:
            return iplist
    msg = '%r is not a list of ip addresses or CIDRs' % values
    raise argparse.ArgumentTypeError(msg)

def portparse(values):
    '''
    parse the ports into a list of ports
    '''
    if values:
        portlist = list()
        for port_string in values.split(','):
            try:
                if '-' in port_string:
                    start, end = port_string.split('-')
                    start, end = int(start), int(end)
                    portlist.extend(range(start, end + 1))
                else:
                    portlist.append(int(port_string))
            except ValueError:
                portlist = None
        if portlist:
            return portlist
    msg = '%r is not a list of ports must only have , - and numeric values' % values
    raise argparse.ArgumentTypeError(msg)

def getscreenshot(parsedargs, url, outputlocation, outputfilename):
    '''
    use the parsed args to get a screenshot of the web page
    '''
    print('getting screenshot for:' + url)
    wkhtmlrun = list()
    wkhtmlrun.append(parsedargs.wkhtmlloc)
    if parsedargs.wkhtmlheight and parsedargs.wkhtmlheight > 0:
        wkhtmlrun.append("--height")
        wkhtmlrun.append(str(parsedargs.wkhtmlheight))
    if parsedargs.wkhtmlwidth and parsedargs.wkhtmlwidth > 0:
        wkhtmlrun.append("--width")
        wkhtmlrun.append(str(parsedargs.wkhtmlwidth))
    if parsedargs.wkhtmlquality and parsedargs.wkhtmlquality > 0:
        wkhtmlrun.append("--quality")
        wkhtmlrun.append(str(parsedargs.wkhtmlquality))
    wkhtmlrun.append(url)
    finalpath = (outputlocation +
                 outputfilename +
                 parsedargs.wkhtmlext)
    wkhtmlrun.append(finalpath)
    subprocess.call(wkhtmlrun)

def callweb(protocol, address, port, request_session):
    '''
    call the web address and return the response
    '''
    resp_dat = None
    connected_web = None
    try:
        #TODO find a better way of checking between http and https
        #try the request http
        connected_web = "{0}{1}:{2}".format(protocol, address, port)
        with request_session.get(connected_web, timeout=TIMEOUTS) as response:
            resp_dat = response
    except ConnectionRefusedError:
        #connection was refused therefore probably no web server
        #might want to add some debugging messages here in the future.
        connected_web = None
        resp_dat = None
    except requests.ConnectionError:
        #same thing here
        connected_web = None
        resp_dat = None
    except requests.ReadTimeout:
        #same thing here
        connected_web = None
        resp_dat = None
    return (resp_dat, connected_web)

def zipfiles(parsedargs, outputlocation):
    '''
    zip up all the files in the output and remove the old folder
    '''
    with zipfile.ZipFile(parsedargs.outputloc + parsedargs.outputzip, 'w', zipfile.ZIP_DEFLATED) as ziph:
        for fil in [f for f in os.listdir(outputlocation) if os.path.isfile(os.path.join(outputlocation, f))]:
            ziph.write(os.path.join(outputlocation, fil), fil)
        shutil.rmtree(outputlocation)

def scan(parsedargs):
    '''
    Scan the ip address ranges and ports for the web servers
    '''
    command = ''
    outputlocation = ''
    for arg in sys.argv:
        command += arg + ' '
    if parsedargs.outputloc:
        outputlocation = parsedargs.outputloc
    if parsedargs.outputzip:
        if '.' not in parsedargs.outputzip:
            parsedargs.outputzip = parsedargs.outputzip + ".zip"
        if '/' in parsedargs.outputzip or '\\' in parsedargs.outputzip:
            #need to remove folders in the output zip name as this will mess with the zipping
            parsedargs.outputzip = parsedargs.outputzip.split('/', 1)[-1]
            parsedargs.outputzip = parsedargs.outputzip.split('\\', 1)[-1]
        tempoutput = parsedargs.outputzip.replace('.', '').replace(':', '')
        outputlocation = outputlocation + tempoutput + "/"
    if parsedargs.allout:
        parsedargs.fileout = outputlocation + parsedargs.allout + '.out'
        parsedargs.xmlout = outputlocation + parsedargs.allout + '.xml'
        parsedargs.jsonout = outputlocation + parsedargs.allout + '.json'
    else:
        if parsedargs.jsonout:
            if '.json' not in parsedargs.jsonout:
                parsedargs.jsonout = parsedargs.jsonout + '.json'
            parsedargs.jsonout = outputlocation + parsedargs.jsonout
        if parsedargs.xmlout:
            if '.xml' not in parsedargs.xmlout:
                parsedargs.xmlout = parsedargs.xmlout + '.xml'
            parsedargs.xmlout = outputlocation + parsedargs.xmlout
        if parsedargs.fileout:
            if '.out' not in parsedargs.fileout:
                parsedargs.fileout = parsedargs.fileout + '.out'
            parsedargs.fileout = outputlocation + parsedargs.fileout
    if outputlocation:
        if not os.path.exists(outputlocation):
            os.makedirs(outputlocation)
    with Output(command, parsedargs.fileout,
                parsedargs.xmlout, parsedargs.jsonout,
                parsedargs.search) as output:
        headers = {'User-Agent':parsedargs.useragent}
        with requests.Session() as sess:
            sess.headers.update(headers)
            sess.verify = False
            if parsedargs.proxy:
                proxies = {
                    'http':parsedargs.proxy,
                    'https':parsedargs.proxy
                }
                sess.proxies.update(proxies)
            for ipadd in parsedargs.ipaddresses:
                print("working ip:" + str(ipadd))
                ipaddresses = [str(ipadd), dict()]
                for port in parsedargs.portlist:
                    print("\tworking port:" + str(port))
                    protocol, url = httporhttps(ipadd, port, sess)
                    response = callweb(protocol, ipadd, port, sess)
                    ipaddresses[1][port] = response[0]
                    if parsedargs.screenshot and response[1]:
                        #TODO need to send the proxy data to the program also.
                        outputfilename = ipadd.replace(".", "_")
                        outputfilename += '-' + str(port)
                        getscreenshot(parsedargs, url, outputlocation, outputfilename)
                output.addresponsedata(ipaddresses)
    #time to zip everything up if we are zipping
    if parsedargs.outputzip:
        zipfiles(parsedargs, outputlocation)

def main():
    '''
    main program
    '''
    parser = argparse.ArgumentParser(description=('Simple program for searching for http/s pages in a range of IP addresses.' +
                                                  ' if it finds one it grabs an image of the rendered page and the html of the home'))
    required_group = parser.add_argument_group('required', 'required arguments')
    required_group.add_argument('ipaddresses',
                                type=ipparse,
                                help='Comma seperated list of IP/CIDR addresses')

    connection_group = parser.add_argument_group('connection', 'Connection arguments')
    connection_group.add_argument('--ports', '-p',
                                  type=portparse,
                                  dest='portlist',
                                  metavar='PORTS',
                                  default='80,443',
                                  help='list of ports to scan for http pages. Comma seperated can use - to denote range')
    connection_group.add_argument('--user_agent', '-u',
                                  dest='useragent',
                                  metavar='USERAGENT',
                                  default=('Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' +
                                           'AppleWebKit/537.36 (KHTML, like Gecko) ' +
                                           'Chrome/60.0.3112.113 Safari/537.36'),
                                  help='Insert your own user agent header string')
    connection_group.add_argument('--proxy',
                                  dest='proxy',
                                  metavar='PROXY',
                                  default=None,
                                  help='Proxy connection data')

    output_group = parser.add_argument_group('output', 'output parameters')
    output_group.add_argument('--output_zip', '-oZ',
                              dest='outputzip',
                              metavar='ZIPNAME',
                              default=None,
                              help='zips all the output including images will create a temporary folder to store everything until it can zip')
    output_group.add_argument('--output_location', '-oL',
                              dest='outputloc',
                              metavar='FOLDERNAME',
                              default='',
                              help='folder to store all output in')
    output_group.add_argument('--output_xml', '-oX',
                              dest='xmlout',
                              metavar='FILENAME',
                              default=None,
                              help='Output to XML file')
    output_group.add_argument('--output_json', '-oJ',
                              dest='jsonout',
                              metavar='FILENAME',
                              default=None,
                              help='Output to json file')
    output_group.add_argument('--output_file', '-oF',
                              dest='fileout',
                              metavar='FILENAME',
                              default=None,
                              help='Output standard output to file')
    output_group.add_argument('--output_all', '-oA',
                              dest='allout',
                              metavar='FILENAME',
                              default=None,
                              help='Output to all file types')

    search_group = parser.add_argument_group('search', 'help search for data in output')
    search_group.add_argument('--search', '-s',
                              dest='search',
                              default=None,
                              help='a string to search for in the html')

    image_group = parser.add_argument_group('image', 'image output handling')
    image_group.add_argument('--screenshot',
                             dest='screenshot',
                             action='store_true',
                             help='take screenshots of the webpages using wkhtmltoimage')
    image_group.add_argument('--wkhtmlloc',
                             dest='wkhtmlloc',
                             metavar='EXELOCATION',
                             default="wkhtmltox/bin/wkhtmltoimage",
                             help='the executable location of the wkhtmltoimage')
    image_group.add_argument('--wkhtmlext',
                             dest='wkhtmlext',
                             metavar='EXT',
                             default=".png",
                             help='the extension of the image to create .png default')
    image_group.add_argument('--wkhtmlheight',
                             dest='wkhtmlheight',
                             metavar='HEIGHT',
                             type=int,
                             default=None,
                             help='the height of the image in real units')
    image_group.add_argument('--wkhtmlwidth',
                             dest='wkhtmlwidth',
                             type=int,
                             metavar='WIDTH',
                             default=None,
                             help='the width of the image in real units')
    image_group.add_argument('--wkhtmlquality',
                             dest='wkhtmlquality',
                             type=int,
                             metavar='QUALITY',
                             default=None,
                             help='the quality of the image between 0 and 100 default is 94')
    parsedargs = parser.parse_args()
    scan(parsedargs)



if __name__ == '__main__':
    main()
