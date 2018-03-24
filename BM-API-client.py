#!/usr/bin/env python2.7
# 
# version 1.2.8     
# torifier is NOT the author of this software "api-client"
#
# I, the author of this software and the sole copyright holder, hereby grant everyone my permission to use this software with the following stipulations:
# 1. Peter Surda from Slovakia (of Grosslingova high school, Bratislava, Slovakia) is not permitted to use my software in any way, shape or form, otherwise he commits a criminal offense and I shall file a criminal complaint against his person with the Police of both Slovakia and Austria where Surda is known to be hiding.
# 2. This license notice and especially the explicit exclusion of Peter Surda from any possible use of my software may not be removed from my software source code.
#
import signal, hashlib, string, xmlrpclib, sys, os, time, urlparse, glob, imghdr
from urllib2 import urlopen, Request
from optparse import OptionParser as OP, IndentedHelpFormatter as IHF
from base64 import b64encode, b64decode
from struct import *
from json import loads as jsld
from zlib import crc32

def signal_handler(signal, frame):
    sys.exit(99)
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def decodeBase58(string, alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'):
    base = len(alphabet); num = 0
    try:
        for char in string: num *= base; num += alphabet.index(char)
    except: return 0
    return num

class varintDecodeError(Exception): pass
def decodeVarint(data):
    if len(data) == 0:  return (0,0)
    firstByte, = unpack('>B',data[0:1])
    if firstByte < 253: return (firstByte,1)
    if firstByte == 253:
        if len(data) < 3:             raise varintDecodeError
        encodedValue, = unpack('>H',data[1:3])
        if encodedValue < 253:        raise varintDecodeError
        return (encodedValue,3)
    if firstByte == 254:
        if len(data) < 5:             raise varintDecodeError
        encodedValue, = unpack('>I',data[1:5])
        if encodedValue < 65536:      raise varintDecodeError
        return (encodedValue,5)
    if firstByte == 255:
        if len(data) < 9:             raise varintDecodeError
        encodedValue, = unpack('>Q',data[1:9])
        if encodedValue < 4294967296: raise varintDecodeError
        return (encodedValue,9)

def decodeAddress(address):
    address = str(address).strip()
    if address[:3] == 'BM-': integer = decodeBase58(address[3:])
    else:                    integer = decodeBase58(address)
    if integer == 0: status = 'invalidcharacters';                return status,0,0,''
    hexdata = hex(integer)[2:-1]
    if len(hexdata) % 2 != 0: hexdata = '0' + hexdata
    data = hexdata.decode('hex'); checksum = data[-4:]
    sha = hashlib.new('sha512'); sha.update(data[:-4]); currentHash = sha.digest()
    sha = hashlib.new('sha512'); sha.update(currentHash)
    if checksum != sha.digest()[0:4]: status = 'checksumfailed';  return status,0,0,''
    try: addressVersionNumber, bytesUsedByVersionNumber = decodeVarint(data[:9])
    except varintDecodeError:         status = 'varintmalformed'; return status,0,0,''
    if addressVersionNumber > 4:      status = 'versiontoohigh';  return status,0,0,''
    elif addressVersionNumber == 0:   status = 'versiontoohigh';  return status,0,0,''
    try: streamNumber, bytesUsedByStreamNumber = decodeVarint(data[bytesUsedByVersionNumber:])
    except varintDecodeError:         status = 'varintmalformed'; return status,0,0,''
    status = 'success'
    if addressVersionNumber == 1:                                 return status,addressVersionNumber,streamNumber,data[-24:-4]
    elif addressVersionNumber == 2 or addressVersionNumber == 3:
        embeddedRipeData = data[bytesUsedByVersionNumber+bytesUsedByStreamNumber:-4]
        if   len(embeddedRipeData) > 20:                          return 'ripetoolong', 0,0,''
        elif len(embeddedRipeData) == 20:                         return status,addressVersionNumber,streamNumber,embeddedRipeData
        elif len(embeddedRipeData) == 19:                         return status,addressVersionNumber,streamNumber,'\x00'+embeddedRipeData
        elif len(embeddedRipeData) == 18:                         return status,addressVersionNumber,streamNumber,'\x00\x00'+embeddedRipeData
        elif len(embeddedRipeData) < 18:                          return 'ripetooshort',0,0,''
        else:                                                     return 'otherproblem',0,0,''
    elif addressVersionNumber == 4:
        embeddedRipeData = data[bytesUsedByVersionNumber+bytesUsedByStreamNumber:-4]
        if   embeddedRipeData[0:1] == '\x00':                     return 'encodingproblem',0,0,''
        elif len(embeddedRipeData) > 20:                          return 'ripetoolong',    0,0,''
        elif len(embeddedRipeData) < 4:                           return 'ripetooshort',   0,0,''
        else: x00string = '\x00' * (20 - len(embeddedRipeData));  return status,addressVersionNumber,streamNumber,x00string+embeddedRipeData

def queryaddress(address, remote, api):
    status, version, stream, ripe = decodeAddress(address)
    if remote:
        try:
            adr = jsld(api.decodeAddress(address))
        except Exception as e: sys.stderr.write('%s\n' % str(e)); sys.exit(1)
        if status != adr['status'] or version != adr['addressVersion'] or stream != adr['streamNumber'] or ripe != b64decode(adr['ripe']):
            sys.stderr.write("Error: The remote address decoding result doesn't match the local result, contact BM developers!\n"); sys.exit(2)
    return status, version, stream, ripe

def lookup(address, identities, contacts, checkenabled = False):
    exist = next((item for item in identities if item['address'] == address), False)
    if checkenabled:
        enabled = False
        if exist: enabled = exist['enabled']
        return exist, enabled
    else:
        exist2 = next((item for item in contacts if item['address'] == address), False)
        return b64decode(exist2['label']) if exist2 else exist['label'] if exist else address

def realid(idsubj, inbox, sentbox):
    for item in inbox+sentbox:
        if item['msgid'] == idsubj or b64encode(str(crc32(item['msgid'])))[:10] == idsubj or idsubj in b64decode(item['subject']): return item['msgid']
    sys.stderr.write('Error: Message not found\n'); sys.exit(3)

def checkmessagestatus(api, ackdata):
    try:                   print('%s,%s' % (ackdata, api.getStatus(ackdata))); return
    except Exception as e: sys.stderr.write('%s\n' % str(e)); sys.exit(4)

def decodebmaddress(api, address, remote, flags, defflags):
    status, version, stream, ripe = queryaddress(address, remote, api)
    output = []
    if not len(flags): flags = defflags
    for flag in flags:
        if   flag == 'a': output.append(address)
        elif flag == 's': output.append(status)
        elif flag == 'v': output.append(version)
        elif flag == 't': output.append(stream)
        elif flag == 'r': output.append(ripe.encode('hex'))
    if output: print ','.join(map(str, output))
    return

def clientstatus(api):
    try:                   status = jsld(api.clientStatus())
    except Exception as e: sys.stderr.write('%s\n' % str(e)); sys.exit(5)
    for item in sorted(status): print '%s: %s' % (item, status[item])
    return

def listinbox(inbox, identities, contacts, reverse, listunread, nosmsgid, tmfmt, flags, defflags):
    for item in sorted(inbox, key=lambda k: k['receivedTime'], reverse = reverse):
        if listunread and item['read']: continue
        output = []
        if not len(flags): flags = defflags
        for flag in flags:
            if   flag == 'i': output.append(item['msgid'] if nosmsgid else b64encode(str(crc32(item['msgid'])))[:10])
            elif flag == 'r': output.append(time.strftime(tmfmt, time.gmtime(float(item['receivedTime']))))
            elif flag == 'e': output.append(item['read'])
            elif flag == 't': output.append(lookup(item['toAddress'], identities, contacts))
            elif flag == 'f': output.append(lookup(item['fromAddress'], identities, contacts))
            elif flag == 's': output.append(b64decode(item['subject']))
        if output: print ','.join(map(str, output))
    return

def listsentbox(sentbox, identities, contacts, reverse, nosmsgid, tmfmt, flags, defflags):
    for item in sorted(sentbox, key=lambda k: k['lastActionTime'], reverse = reverse):
        output = []
        if not len(flags): flags = defflags
        for flag in flags:
            if   flag == 'i': output.append(item['msgid'] if nosmsgid else b64encode(str(crc32(item['msgid'])))[:10])
            elif flag == 'a': output.append(item['ackData'])
            elif flag == 'l': output.append(time.strftime(tmfmt, time.gmtime(float(item['lastActionTime']))))
            elif flag == 'u': output.append(item['status'])
            elif flag == 't': output.append(lookup(item['toAddress'], identities, contacts))
            elif flag == 'f': output.append(lookup(item['fromAddress'], identities, contacts))
            elif flag == 's': output.append(b64decode(item['subject']))
        if output: print ','.join(map(str, output))
    return

def listidentities(identities, reverse, remote, api, flags, defflags):
    for item in sorted(identities, key=lambda k: k['label'].lower(), reverse = reverse):
        output = []
        if not len(flags): flags = defflags
        for flag in flags:
            if   flag == 'a': output.append(item['address'])
            elif flag == 'e': output.append(item['enabled'])
            elif flag == 'v': output.append(queryaddress(item['address'], remote, api)[1])
            elif flag == 't': output.append(item['stream'])
            elif flag == 'c': output.append(item['chan'])
            elif flag == 'l': output.append(item['label'])
        if output: print ','.join(map(str, output))
    return

def listcontacts(contacts, reverse, remote, api, flags, defflags):
    for item in sorted(contacts, key=lambda k: b64decode(k['label']).lower(), reverse = reverse):
        output = []
        if not len(flags): flags = defflags
        for flag in flags:
            if   flag == 'a': output.append(item['address'])
            elif flag == 'v': output.append(queryaddress(item['address'], remote, api)[1])
            elif flag == 't': output.append(queryaddress(item['address'], remote, api)[2])
            elif flag == 'l': output.append(b64decode(item['label']))
        if output: print ','.join(map(str, output))
    return

def readim(api, inboxm, inbox, identities, contacts, setread, nosmsgid, tmfmt, delread, flags, defflags, fwdto, fwdh, ttl):
    try:                   message, = jsld(api.getInboxMessageByID(realid(inboxm, inbox, []), *((setread,) if setread else ())))['inboxMessage']
    except Exception as e: sys.stderr.write('%s\n' % str(e)); sys.exit(6)
    output = []
    if not len(fwdto) and not len(flags): flags = defflags
    for flag in flags:
        if   flag == 'i': output.append(message['msgid'] if nosmsgid else b64encode(str(crc32(message['msgid'])))[:10])
        elif flag == 'r': output.append(time.strftime(tmfmt, time.gmtime(float(message['receivedTime']))))
        elif flag == 'e': output.append(message['read'])
        elif flag == 't': output.append(lookup(message['toAddress'], identities, contacts))
        elif flag == 'f': output.append(lookup(message['fromAddress'], identities, contacts))
        elif flag == 's': output.append(b64decode(message['subject']))
    if output: print ','.join(map(str, output))
    if 'm' in flags:
        m = b64decode(message['message'])
        if m.find('Part of the message is corrupt. The message cannot be displayed the normal way.'): print m
        else:
            if sys.platform == 'win32': import msvcrt; msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
            sys.stdout.write(eval(m[81:], {'__builtins__': None}))
    if len(fwdto):
        fwdsubj = ''; fwdmsg = ''
        if fwdh:
            fwdsubj = 'FW: '
            fwdmsg = 'Forwarded at %s, original sender: %s\n\n\n' % (time.strftime(tmfmt, time.gmtime()), message['fromAddress'])
        sendbm(api, identities, message['toAddress'], fwdto, fwdsubj+b64decode(message['subject']), fwdmsg+b64decode(message['message']), ttl)
    if delread: api.trashInboxMessage(message['msgid'])
    return

def readsm(api, sentm, sentbox, identities, contacts, nosmsgid, tmfmt, delread, flags, defflags, fwdto, fwdh, ttl):
    try:                   message, = jsld(api.getSentMessageByID(realid(sentm, [], sentbox)))['sentMessage']
    except Exception as e: sys.stderr.write('%s\n' % str(e)); sys.exit(7)
    output = []
    if not len(fwdto) and not len(flags): flags = defflags
    for flag in flags:
        if   flag == 'i': output.append(message['msgid'] if nosmsgid else b64encode(str(crc32(message['msgid'])))[:10])
        elif flag == 'a': output.append(message['ackData'])
        elif flag == 'l': output.append(time.strftime(tmfmt, time.gmtime(float(message['lastActionTime']))))
        elif flag == 'u': output.append(message['status'])
        elif flag == 't': output.append(lookup(message['toAddress'], identities, contacts))
        elif flag == 'f': output.append(lookup(message['fromAddress'], identities, contacts))
        elif flag == 's': output.append(b64decode(message['subject']))
    if output: print ','.join(map(str, output))
    if 'm' in flags:
        m = b64decode(message['message'])
        if m.find('Part of the message is corrupt. The message cannot be displayed the normal way.'): print m
        else:
            if sys.platform == 'win32': import msvcrt; msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
            sys.stdout.write(eval(m[81:], {'__builtins__': None}))
    if len(fwdto):
        fwdsubj = ''; fwdmsg = ''
        if fwdh:
            fwdsubj = 'FW: '
            fwdmsg = 'Forwarded at %s, original recipient: %s\n\n\n' % (time.strftime(tmfmt, time.gmtime()), message['toAddress'])
        sendbm(api, identities, message['fromAddress'], fwdto, b64decode(message['subject']), b64decode(message['message']), ttl)
    if delread: api.trashSentMessage(message['msgid'])
    return

def readsa(api, readack, identities, contacts, nosmsgid, tmfmt, delread, flags, defflags, fwdto, fwdh, ttl):
    try:                   message, = jsld(api.getSentMessageByAckData(readack))['sentMessage']
    except Exception as e: sys.stderr.write('%s\n' % str(e)); sys.exit(8)
    output = []
    if not len(fwdto) and not len(flags): flags = defflags
    for flag in flags:
        if   flag == 'i': output.append(message['msgid'] if nosmsgid else b64encode(str(crc32(message['msgid'])))[:10])
        elif flag == 'a': output.append(message['ackData'])
        elif flag == 'l': output.append(time.strftime(tmfmt, time.gmtime(float(message['lastActionTime']))))
        elif flag == 'u': output.append(message['status'])
        elif flag == 't': output.append(lookup(message['toAddress'], identities, contacts))
        elif flag == 'f': output.append(lookup(message['fromAddress'], identities, contacts))
        elif flag == 's': output.append(b64decode(message['subject']))
    if output: print ','.join(map(str, output))
    if 'm' in flags:
        m = b64decode(message['message'])
        if m.find('Part of the message is corrupt. The message cannot be displayed the normal way.'): print m
        else:
            if sys.platform == 'win32': import msvcrt; msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
            sys.stdout.write(eval(m[81:], {'__builtins__': None}))
    if len(fwdto):
        fwdsubj = ''; fwdmsg = ''
        if fwdh:
            fwdsubj = 'FW: '
            fwdmsg = 'Forwarded at %s, original recipient: %s\n\n\n' % (time.strftime(tmfmt, time.gmtime()), message['toAddress'])
        sendbm(api, identities, message['fromAddress'], fwdto, b64decode(message['subject']), b64decode(message['message']), ttl)
    if delread: api.trashSentMessage(message['msgid'])
    return

def trashmessage(api, msgidsubj, inbox, sentbox, q = False):
    try:
        if not q: print('%s,%s' % (msgidsubj, api.trashMessage(realid(msgidsubj, inbox, sentbox))))
        else:                                 api.trashMessage(realid(msgidsubj, inbox, sentbox))
        return
    except Exception as e: sys.stderr.write('%s\n' % str(e)); sys.exit(9)

def trashinboxmessage(api, msgidsubj, inbox, q = False):
    try:
        if not q: print('%s,%s' % (msgidsubj, api.trashInboxMessage(realid(msgidsubj, inbox, []))))
        else:                                 api.trashInboxMessage(realid(msgidsubj, inbox, []))
        return
    except Exception as e: sys.stderr.write('%s\n' % str(e)); sys.exit(10)

def trashsentmessage(api, msgidsubj, sentbox, q = False):
    try:
        if not q: print('%s,%s' % (msgidsubj, api.trashSentMessage(realid(msgidsubj, [], sentbox))))
        else:                                 api.trashSentMessage(realid(msgidsubj, [], sentbox))
        return
    except Exception as e: sys.stderr.write('%s\n' % str(e)); sys.exit(11)

def trashmessagebyack(api, delack, q = False):
    try:
        if not q: print('%s,%s' % (delack, api.trashSentMessageByAckData(delack)))
        else:                              api.trashSentMessageByAckData(delack)
        return
    except Exception as e: sys.stderr.write('%s\n' % str(e)); sys.exit(12)

def vacuum(api, q = False):
    try:
        if not q: print api.deleteAndVacuum()
        else:           api.deleteAndVacuum()
        return
    except Exception as e: sys.stderr.write('%s\n' % str(e)); sys.exit(13)

def deleterandomidentities(api, randomlabel, identities):
    for randomaddr in (item['address'] for item in identities if not item['label'].find(randomlabel)): api.deleteAddress(randomaddr)
    return

def imgoptim(img, ftype, colors, bits, quality, resize, maxx, maxy, debug):
    if debug: print('DEBUG: %s image original size: %d' % (ftype.upper(), len(img)))
    try:                     from PIL import Image
    except ImportError as e: sys.stderr.write('%s\n' % str(e)); sys.exit(14)
    from io import BytesIO
    imgio = BytesIO(); imgio.write(img); imgpil = Image.open(imgio)
    if debug: print('DEBUG: image resolution: %dx%d' % (imgpil.size[0], imgpil.size[1]))
    if resize != 100:
        if debug: print('DEBUG: resizing to %d%%' % resize)
        imgpil = imgpil.resize((int(resize / 100.0 * imgpil.size[0]), int(resize / 100.0 * imgpil.size[1])), Image.ANTIALIAS)
        if debug: print('DEBUG: new image resolution: %dx%d' % (imgpil.size[0], imgpil.size[1]))
    if (maxx > 0 and maxx < imgpil.size[0]) or (maxy > 0 and maxy < imgpil.size[1]):
        if maxx > 0 and (not maxy or int(maxx*1.0/imgpil.size[0]*imgpil.size[1]) < maxy): maxy = int(maxx*1.0/imgpil.size[0]*imgpil.size[1])
        else:                                                                             maxx = int(maxy*1.0/imgpil.size[1]*imgpil.size[0])
        if debug: print('DEBUG: resizing to %dx%d' % (maxx, maxy))
        imgpil = imgpil.resize((maxx, maxy), Image.ANTIALIAS)
        if debug: print('DEBUG: new image resolution: %dx%d' % (imgpil.size[0], imgpil.size[1]))
    if colors >= 1 and colors <= 256:
        if debug: print('DEBUG: reducing the number of colors to %d' % colors)
        imgpil = imgpil.convert('P', colors = colors, palette = Image.ADAPTIVE)
    if not (colors >= 1 and colors <= 256) or ftype == 'jpeg': imgpil = imgpil.convert('RGB')
    imgpil.load(); imgio.seek(0); imgio.truncate(0); imgpil.save(imgio, format = ftype, optimize = True, quality = quality, bits = bits)
    if debug: print('DEBUG: final size: %d (%.1f%%)' % (len(imgio.getvalue()), 100.0*len(imgio.getvalue())/len(img)))
    return imgio.getvalue()

def sendbm(api, identities, fromaddr, toaddr, subj, msg, ttl, wait=False, empty=False, delsent=False, fromdelete=False, randlbl='', remote=False, q=False):
    if not empty and not len(subj+msg): sys.stderr.write('Error: Empty message not allowed\n'); sys.exit(15)
    if len(subj+msg) > (2 ** 18 - 500): sys.stderr.write('Error: The BM message is by %d bytes too long\n' % (len(subj+msg)-(2 ** 18 - 500))); sys.exit(16)
    if not len(fromaddr)*len(toaddr):   sys.stderr.write("Error: Both 'From' and 'To' addresses must be set\n"); sys.exit(17)
    if fromaddr == 'random':
        try:                   fromaddr = api.createRandomAddress(b64encode(randlbl+str(time.time())))
        except Exception as e: sys.stderr.write('%s\n' % str(e)); sys.exit(18)
        identities = jsld(api.listAddresses())['addresses']
    elif fromdelete: fromdelete = False
    exist, enabled = lookup(fromaddr, identities, [], True)
    if not exist:   sys.stderr.write("Error: The 'From' address %s does not exist\n" % fromaddr); sys.exit(19)
    if not enabled: sys.stderr.write("Error: The 'From' address %s exists but isn't enabled\n" % fromaddr); sys.exit(20)
    if toaddr == 'broadcast':
        try:                   ackData = api.sendBroadcast(fromaddr, b64encode(subj), b64encode(msg), 2, eval(ttl, {'__builtins__': None})*60)
        except Exception as e: sys.stderr.write('%s\n' % str(e)); sys.exit(21)
    else:
        if not queryaddress(toaddr, remote, api)[0] == 'success': sys.stderr.write("Error: The 'To' address %s does not validate\n" % toaddr); sys.exit(22)
        try:                   ackData = api.sendMessage(toaddr, fromaddr, b64encode(subj), b64encode(msg), 2, eval(ttl, {'__builtins__': None})*60)
        except Exception as e: sys.stderr.write('%s\n' % str(e)); sys.exit(23)
    if not q: print ackData
    while (wait or fromdelete or delsent) and api.getStatus(ackData).find('msgsent'): time.sleep(1)
    if fromdelete: api.deleteAddress(fromaddr)
    if delsent: api.trashSentMessageByAckData(ackData)
    return

class MyOP(OP):
    def format_epilog(self, epilog): return '\n' + self.epilog + '\n' if self.epilog else ''

class MyIHF(IHF):
    def format_usage(self, usage): return usage + '\n'
    def format_option(self, option):
        result = []; opts = self.option_strings[option]; opt_width = self.help_position - self.current_indent - 2
        if len(opts) > opt_width: opts = '%*s%s\n'   % (self.current_indent, '', opts);            indent_first = self.help_position
        else:                     opts = '%*s%-*s  ' % (self.current_indent, '', opt_width, opts); indent_first = 0; result.append(opts)
        if option.help:
            help_lines = string.split(self.expand_default(option), '\n')
            result.append ('%*s%s\n' % (indent_first, '', help_lines[0]))
            result.extend(['%*s%s\n' % (self.help_position, '', line) for line in help_lines[1:]])
        elif opts[-1] != '\n': result.append('\n')
        return ''.join(result)

def main():
  progname    = 'Bitmessage API mini client'
  progversion = 'v1.28'
  deffromaddr = 'BM-2cW67GEKkHGonXKZLCzouLLxnLym3azS8r'
  deftoaddr   = 'BM-2cW67GEKkHGonXKZLCzouLLxnLym3azS8r'
  defqflags   = 'asvtr'
  deflflags   = 'iretfs'
  deflsflags  = 'ilutfs'
  defliflags  = 'aevtcl'
  deflcflags  = 'avtl'
  defrflags   = 'iretfsm'
  defrsflags  = 'ilutfsm'
  randomlabel = 'apiclientrandom'
  useragent = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36'
  usage  = '%s %s\n\n' % (progname, progversion)
  usage += 'Usage: %prog [options] [1st_line_of_message] [2nd_line_of_message]...'
  epilog  = "If the 'From' address (-f) is 'random' then a new random address is generated,\n"
  epilog += "used and (if --fd is specified) immediately afterwards deleted (implies -w).\n"
  epilog += "If the 'To' address (-t) is 'broadcast' then the message is broadcasted to all\n"
  epilog += "subscribers of given 'From' address.\n"
  epilog += "Embedded (-e) can be a filepath or multiple filepaths separated by colon (:),\n"
  epilog += "url or 'clipboard' in which case the clipboard content is loaded and used as if\n"
  epilog += "it was the actual -e value. Filepath(s) may also contain wildcards and\n"
  epilog += "environment variables.\n\n"
  epilog += "Description of the various flags used:\n"
  epilog += "  address: (a)ddress, (s)tatus, (v)ersion, s(t)ream, (r)ipe\n"
  epilog += "  inbox: msg(i)d, (r)eceived, r(e)ad, (t)o, (f)rom, (s)ubject, (m)sg\n"
  epilog += "  sentbox: msg(i)d, (a)ckdata, (l)ast, stat(u)s, (t)o, (f)rom, (s)ubject, (m)sg\n"
  epilog += "  identities: (a)ddress, (e)nabled, (v)ersion, s(t)ream, (c)han, (l)abel\n"
  epilog += "  contacts: (a)ddress, (v)ersion, s(t)ream, (l)abel"
  p = MyOP(formatter = MyIHF(width = 80), usage = usage, epilog = epilog, version = '%s %s' % (progname, progversion))
  p.add_option('-a',         dest='host',      default = 'localhost',                help = "API host (default 'localhost')")
  p.add_option('-i',         dest='port',      default = 8442, type = 'int',         help = "API port (default 8442)")
  p.add_option('-u',         dest='username',  default = 'username',                 help = "API username (default 'username')")
  p.add_option('-p',         dest='password',  default = 'password',                 help = "API password (default 'password')")
  p.add_option('-f',         dest='fromaddr',  default = deffromaddr,                help = "'From' address (default '%s')" % deffromaddr)
  p.add_option('--fd',       dest='fromdelete',default = False,action = 'store_true',help = "- if 'random' address was used delete it afterwards (implies -w)")
  p.add_option('-t',         dest='toaddr',    default = deftoaddr,                  help = "'To' address (default '%s')" % deftoaddr)
  p.add_option('-s',         dest='subject',   default = '',                         help = "Message subject")
  p.add_option('--st',       dest='subjtime',  default = False,action = 'store_true',help = "Append the timestamp to the subject (formatted with --tf)")
  p.add_option('-e',         dest='embedded',  default = '',                         help = "Embed (base64) an image from a file, or multiple files, or url")
  p.add_option('--edetect',  dest='edetect',   default = False,action = 'store_true',help = "- if image type autodetection fails guess it from the extension")
  p.add_option('--en',       dest='embn',      default = 0, type = 'int',            help = "- if -e expands into multiple files use only first N files")
  p.add_option('--em',       dest='embsort',   default = False,action = 'store_true',help = "- sort files by modification time, the most recent first")
  p.add_option('--eo',       dest='emboptim',  default = False,action = 'store_true',help = "- optimize/resize GIF, JPEG or PNG image (requires Pillow)")
  p.add_option('--eoc',      dest='colors',    default = 0, type = 'int',            help = "- - reduce the number of colors (1-256)")
  p.add_option('--eob',      dest='bits',      default = 8, type = 'int',            help = "- - PNG only: bits per pixel (requires --eoc, default 8)")
  p.add_option('--eoq',      dest='qualit',    default = 75, type = 'int',           help = "- - JPEG only: image quality (default 75)")
  p.add_option('--eor',      dest='resize',    default = 100, type = 'int',          help = "- - resize to the given percentage (default 100)")
  p.add_option('--eorx',     dest='maxx',      default = 0, type = 'int',            help = "- - shrink to the given pixel width")
  p.add_option('--eory',     dest='maxy',      default = 0, type = 'int',            help = "- - shrink to the given pixel height")
  p.add_option('--eodebug',  dest='odebug',    default = False,action = 'store_true',help = "- - show debug messages")
  p.add_option('--es',       dest='embsubj',   default = False,action = 'store_true',help = "- append embedded filename (if single) or url to the subject")
  p.add_option('-m',         dest='appendfl',  default = '',                         help = "Append the file content (binary)")
  p.add_option('--ms',       dest='appsubj',   default = False,action = 'store_true',help = "- append appended filename to the subject")
  p.add_option('--ttl',      dest='ttl',       default = '60*24*4',                  help = "Message TTL in minutes (default '60*24*4')")
  p.add_option('-n',         dest='empty',     default = False,action = 'store_true',help = "Allow empty message")
  p.add_option('-w',         dest='wait',      default = False,action = 'store_true',help = "Wait until the message is sent out")
  p.add_option('-c',         dest='ackdata',   default = '',                         help = "Check a sent message status by ackdata")
  p.add_option('-q',         dest='address',   default = '',                         help = "Decode a BM address (locally)\n"                                 +
                                                                                            " (default flags '%s')" % defqflags)
  p.add_option('--qr',       dest='remote',    default = False,action = 'store_true',help = "- perform all address decoding also remotely and compare results")
  p.add_option('-l',         dest='listm',     default = False,action = 'store_true',help = "List all inbox messages (sorted by received time, ascending)\n"  +
                                                                                            " (default flags '%s')" % deflflags)
  p.add_option('--lu',       dest='listunread',default = False,action = 'store_true',help = "- list only unread inbox messages")
  p.add_option('--ls',       dest='lists',     default = False,action = 'store_true',help = "List all sent messages (sorted by last action time, ascending)\n"+
                                                                                            " (default flags '%s')" % deflsflags)
  p.add_option('--li',       dest='listi',     default = False,action = 'store_true',help = "List all identities (sorted by label, case-insensitive)\n"       +
                                                                                            " (default flags '%s')" % defliflags)
  p.add_option('--lc',       dest='listc',     default = False,action = 'store_true',help = "List all contacts (sorted by label, case-insensitive)\n"         +
                                                                                            " (default flags '%s')" % deflcflags)
  p.add_option('-r',         dest='inboxm',    default = '',                         help = "Read an inbox message by msgid (simplified or real) or subject\n"+
                                                                                            " (default flags '%s')" % defrflags)
  p.add_option('--rr',       dest='setread',   default = False,action = 'store_true',help = "- set read status")
  p.add_option('--rs',       dest='sentm',     default = '',                         help = "Read a sent message by msgid (simplified or real) or subject\n"  +
                                                                                            " (default flags '%s')" % defrsflags)
  p.add_option('--ra',       dest='readack',   default = '',                         help = "Read a sent message by ackdata\n"                                +
                                                                                            " (default flags '%s')" % defrsflags)
  p.add_option('--fwd',      dest='fwdto',     default = '',                         help = "Forward the message after reading")
  p.add_option('--fwdheader',dest='fwdh',      default = False,action = 'store_true',help = "- prepend 'FW: ' to the subject and a short notice to the body")
  p.add_option('-d',         dest='msgidsubj', default = '',                         help = "Trash a message by msgid (simplified or real) or subject")
  p.add_option('--deli',     dest='imsg',      default = '',                         help = "Trash an inbox message by msgid (simplified or real) or subject")
  p.add_option('--dels',     dest='smsg',      default = '',                         help = "Trash a sentbox message by msgid (simplified or real) or subject")
  p.add_option('--da',       dest='delack',    default = '',                         help = "Trash a sent message by ackdata")
  p.add_option('--dr',       dest='delread',   default = False,action = 'store_true',help = "Trash the message after reading")
  p.add_option('--ds',       dest='delsent',   default = False,action = 'store_true',help = "Trash the message after sending (implies -w)")
  p.add_option('--vacuum',   dest='vacuum',    default = False,action = 'store_true',help = "Delete all trashed messages and vacuum (compact) the database")
  p.add_option('--delrandom',dest='delrandom', default = False,action = 'store_true',help = "Delete all random identities generated by -f random")
  p.add_option('--status',   dest='status',    default = False,action = 'store_true',help = "Get client status information")
  p.add_option('--fl',       dest='flags',     default = '',                         help = "Flags")
  p.add_option('--rev',      dest='reverse',   default = False,action = 'store_true',help = "Reverse sorting order")
  p.add_option('--nosmsgid', dest='nosmsgid',  default = False,action = 'store_true',help = "Don't show simplified msgid")
  p.add_option('--tf',       dest='tmfmt',     default = '%Y-%m-%d %H:%M:%S UTC',    help = "UTC time format string (default '%Y-%m-%d %H:%M:%S UTC')")
  p.add_option('--out2clip', dest='out2clip',  default = False,action = 'store_true',help = "Save the whole message body to clipboard instead of actual send")
  p.add_option('--quiet',    dest='quiet',     default = False,action = 'store_true',help = "Suppress output where not required")
  (o, args) = p.parse_args()
  api = xmlrpclib.ServerProxy('http://%s:%s@%s:%d/' % (o.username, o.password, o.host, o.port))
  if len(o.ackdata):   checkmessagestatus(api, o.ackdata);                                                                                           sys.exit()
  if len(o.address):   decodebmaddress(api, o.address, o.remote, o.flags, defqflags);                                                                sys.exit()
  if o.status:         clientstatus(api);                                                                                                            sys.exit()
  try:                   identities = jsld(api.listAddresses())['addresses']
  except Exception as e: sys.stderr.write('%s\n' % str(e)); sys.exit(24)
  inbox = []
  if o.listm or len(o.inboxm) or len(o.msgidsubj) or len(o.imsg):
      try:                   inbox = jsld(api.getAllInboxMessages())['inboxMessages']
      except Exception as e: sys.stderr.write('%s\n' % str(e)); sys.exit(25)
  sentbox = []
  if o.lists or len(o.sentm) or len(o.msgidsubj) or len(o.smsg):
      try:                   sentbox = jsld(api.getAllSentMessages())['sentMessages']
      except Exception as e: sys.stderr.write('%s\n' % str(e)); sys.exit(26)
  contacts = []
  if o.listm or len(o.inboxm) or o.lists or len(o.sentm) or len(o.readack) or o.listc:
      try:                   contacts = jsld(api.listAddressBookEntries())['addresses']
      except Exception as e: sys.stderr.write('%s\n' % str(e)); sys.exit(27)
  if o.listm:          listinbox(inbox, identities, contacts, o.reverse, o.listunread, o.nosmsgid, o.tmfmt, o.flags, deflflags);                     sys.exit()
  if o.lists:          listsentbox(sentbox, identities, contacts, o.reverse, o.nosmsgid, o.tmfmt, o.flags, deflsflags);                              sys.exit()
  if o.listi:          listidentities(identities, o.reverse, o.remote, api, o.flags, defliflags);                                                    sys.exit()
  if o.listc:          listcontacts(contacts, o.reverse, o.remote, api, o.flags, deflcflags);                                                        sys.exit()
  if len(o.inboxm):    readim(api,o.inboxm,inbox,identities,contacts,o.setread,o.nosmsgid,o.tmfmt,o.delread,o.flags,defrflags,o.fwdto,o.fwdh,o.ttl); sys.exit()
  if len(o.sentm):     readsm(api,o.sentm,sentbox,identities,contacts,o.nosmsgid,o.tmfmt,o.delread,o.flags,defrsflags,o.fwdto,o.fwdh,o.ttl);         sys.exit()
  if len(o.readack):   readsa(api,o.readack,identities,contacts,o.nosmsgid,o.tmfmt,o.delread,o.flags,defrsflags,o.fwdto,o.fwdh,o.ttl);               sys.exit()
  if len(o.msgidsubj): trashmessage(api, o.msgidsubj, inbox, sentbox, o.quiet);                                                                      sys.exit()
  if len(o.imsg):      trashinboxmessage(api, o.imsg, inbox, o.quiet);                                                                               sys.exit()
  if len(o.smsg):      trashsentmessage(api, o.smsg, sentbox, o.quiet);                                                                              sys.exit()
  if len(o.delack):    trashmessagebyack(api, o.delack, o.quiet);                                                                                    sys.exit()
  if o.vacuum:         vacuum(api, o.quiet);                                                                                                         sys.exit()
  if o.delrandom:      deleterandomidentities(api, randomlabel, identities);                                                                         sys.exit()
  subj = o.subject
  if o.subjtime:
      if len(subj): subj += ' '
      subj += time.strftime(o.tmfmt, time.gmtime())
  msg = ''
  if len(args): msg += '\n'.join(args)
  clip = None
  if len(o.embedded):
      if o.embedded == 'clipboard':
          try:
              from PyQt4 import QtGui; app = QtGui.QApplication([]); clip = app.clipboard()
              if not clip.mimeData().hasText() and not clip.mimeData().hasUrls(): raise Exception('Error: cannot detect clipboard content format')
              o.embedded = str(clip.text())
          except Exception as e: sys.stderr.write('%s\n' % str(e)); sys.exit(28)
      parts = urlparse.urlsplit(o.embedded)
      if parts.scheme and parts.netloc:
          try:                   u = urlopen(Request(o.embedded, headers = {'User-Agent': useragent})).read()
          except Exception as e: sys.stderr.write('%s\n' % str(e)); sys.exit(29)
          if len(msg): msg += '\n<br/>'
          ftype = imghdr.what(None, u)
          if o.emboptim and ftype in ['gif','jpeg','png']: img = imgoptim(u,ftype,o.colors,o.bits,o.qualit,o.resize,o.maxx,o.maxy,o.odebug)
          else:                                            img = u
          if ftype is None and o.edetect: spl = o.embedded.split('.'); ftype = spl[len(spl)-1].lower()
          if ftype is None or not len(ftype): sys.stderr.write('Error: cannot detect image format of %s\n' % o.embedded); sys.exit(30)
          msg += '<img src="data:image/%s;base64,%s" />' % (ftype, b64encode(img).replace('\n', ''))
          if o.embsubj:
              if len(subj): subj += ' '
              subj += o.embedded
      else:
          listx = []; n = 0
          for item in o.embedded.split(':'): listx.extend(glob.glob(os.path.expandvars(os.path.expanduser(item))))
          if o.embsort: list = [item for item in sorted(listx, key=os.path.getmtime, reverse=True) if not os.path.isdir(item)]
          else:         list = [item for item in listx if not os.path.isdir(item)]
          for item in list:
              n += 1
              if o.embn > 0 and n > o.embn: break
              try:
                  with open(item, 'rb') as f:
                      if len(msg): msg += '\n<br/>'
                      ftype = imghdr.what(item)
                      if o.emboptim and ftype in ['gif','jpeg','png']: img = imgoptim(f.read(),ftype,o.colors,o.bits,o.qualit,o.resize,o.maxx,o.maxy,o.odebug)
                      else:                                            img = f.read()
                      if ftype is None and o.edetect: ftype = os.path.splitext(item)[1][1:].lower()
                      if ftype is None or not len(ftype): sys.stderr.write('Error: cannot detect image format of %s\n' % item); sys.exit(31)
                      msg += '<img src="data:image/%s;base64,%s" />' % (ftype, b64encode(img).replace('\n', ''))
                      if (len(list) == 1 or o.embn == 1) and o.embsubj:
                          if len(subj): subj += ' '
                          subj += os.path.basename(item)
              except Exception as e: sys.stderr.write('%s\n' % str(e)); sys.exit(32)
  if len(o.appendfl):
      try:
          with open(o.appendfl, 'rb') as f:
              if len(o.embedded): msg += '<br/>\n'
              msg += f.read()
              if o.appsubj:
                  if len(subj): subj += ' '
                  subj += os.path.basename(o.appendfl)
      except Exception as e: sys.stderr.write('%s\n' % str(e)); sys.exit(33)
  if o.out2clip:
      try:
          if not clip: from PyQt4 import QtGui; app = QtGui.QApplication([]); clip = app.clipboard()
          clip.setText(msg)
          sys.exit()
      except Exception as e: sys.stderr.write('%s\n' % str(e)); sys.exit(34)
  sendbm(api, identities, o.fromaddr, o.toaddr, subj, msg, o.ttl, o.wait, o.empty, o.delsent, o.fromdelete, randomlabel, o.remote, o.quiet)

if __name__ == '__main__': main()
