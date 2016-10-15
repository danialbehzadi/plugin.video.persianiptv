# -*- coding: utf-8 -*-
import urllib
import urllib2
import re
import os
import xbmcplugin
import xbmcgui
import xbmcaddon
import xbmcvfs
import traceback
import cookielib,base64,requests
import errno
from socket import error as socket_error
import socket
from BeautifulSoup import BeautifulStoneSoup, BeautifulSoup, BeautifulSOAP
viewmode=500
try:
    from xml.sax.saxutils import escape
except: traceback.print_exc()
try:
    import json
except:
    import simplejson as json
import time
tsdownloader=False

class NoRedirection(urllib2.HTTPErrorProcessor):
   def http_response(self, request, response):
       return response
   https_response = http_response
	
REMOTE_DBG=False;
if REMOTE_DBG:
    # Make pydev debugger works for auto reload.
    # Note pydevd module need to be copied in XBMC\system\python\Lib\pysrc
    try:
        import pysrc.pydevd as pydevd
    # stdoutToServer and stderrToServer redirect stdout and stderr to eclipse console
        pydevd.settrace('localhost', stdoutToServer=True, stderrToServer=True)
    except ImportError:
        sys.stderr.write("Error: " +
            "You must add org.python.pydev.debug.pysrc to your PYTHONPATH.")
        sys.exit(1)


addon = xbmcaddon.Addon('plugin.video.persianiptv')
addon_version = addon.getAddonInfo('version')
profile = xbmc.translatePath(addon.getAddonInfo('path').decode('utf-8'))
home = xbmc.translatePath(addon.getAddonInfo('path').decode('utf-8'))
artpath = xbmc.translatePath(os.path.join('special://home/addons/plugin.video.persianiptv/Images/art/'))
home2 = xbmc.translatePath(os.path.join('special://home/addons/plugin.video.persianiptv/'))
history = os.path.join(home, 'history')
REV = os.path.join(home, 'list_revision')
icon = os.path.join(home, 'icon.png')
FANART = os.path.join(home, 'fanart.jpg')
source_file = os.path.join(home, 'source_file')
functions_dir = home
isitrandom = False
Cookie=''
serverNumber = 0

if addon.getSetting('setup') == 'false':
	dlg = xbmcgui.Dialog()
	dlg.ok('[COLOR red]P[/COLOR][COLOR white]arsiLand[/COLOR]','Lotfan username va password khod ra vared konid. Jahate ','kharid username be ID Telegram zir message dahid.','Password baraye moshtarakin sherkate [COLOR=green][B]Zero One[/COLOR][/B] raygan ast!! [COLOR=red][B]Telegram:[/COLOR][/B]https://telegram.me/Parsilandd [COLOR=red][B]email:[/COLOR][/B]info@parsiland.net')
	retval = dlg.input('Please enter your username', type=xbmcgui.INPUT_ALPHANUM)
	if retval and len(retval) > 0:
		addon.setSetting('usern', str(retval))
		username = addon.getSetting('usern')
	else:
		dlg.ok('[COLOR red]P[/COLOR][COLOR white]arsiLand[/COLOR]','You should enter your username.','Please try again.')
		quit()
	retval = dlg.input('Please enter your password' , type=xbmcgui.INPUT_ALPHANUM, option=xbmcgui.ALPHANUM_HIDE_INPUT)
	if retval and len(retval) > 0:
		addon.setSetting('passw', str(retval))
		addon.setSetting('setup', 'true')
	else:
		dlg.ok('[COLOR red]P[/COLOR][COLOR white]arsiLand[/COLOR]','You should enter your password.','Please try again.')
		quit()
communityfiles = os.path.join(profile, 'LivewebTV')
debug = addon.getSetting('debug')


def addon_log(string):
    if debug == 'true':
        xbmc.log("[addon.ParsiLand-%s]: %s" %(addon_version, string))

def getSources(source):
	try:
		if os.path.exists(source_file)==True:
			sources = json.loads(open(source_file,"r").read())
			if len(sources) > 1:
				for i in sources:
					try:
						## for pre 1.0.8 sources
						if isinstance(i, list):
							addDir(i[0].encode('utf-8'),i[1].encode('utf-8'),1,icon,FANART,'','','','','source')
						else:
							thumb = icon
							fanart = FANART
							desc = ''
							date = ''
							credits = ''
							genre = ''
							if i.has_key('thumbnail'):
								thumb = i['thumbnail']
							if i.has_key('fanart'):
								fanart = i['fanart']
							if i.has_key('description'):
								desc = i['description']
							if i.has_key('date'):
								date = i['date']
							if i.has_key('genre'):
								genre = i['genre']
							if i.has_key('credits'):
								credits = i['credits']
							addDir(i['title'].encode('utf-8'),i['url'].encode('utf-8'),1,thumb,fanart,desc,genre,date,credits,'source')
					except: traceback.print_exc()
			else:
				if len(sources) == 1:
					if isinstance(sources[0], list):
						getData(sources[0][1].encode('utf-8'),FANART)
					else:
						getData(sources[0]['url'], sources[0]['fanart'])
			addDir('Random IPTV Channels','',1338,artpath+'random.png',fanart,'from this section you can access millions! of IPTV channels posted on the net. but these channels arent perpetual.',genre,date,credits,'source')
			addDir('IranProud','',98,artpath+'iranproud.png',fanart,'IranProud website Movies And Series archive ...',genre,date,credits,'source')
			addDir('Sports','',90,artpath+'sports.png',fanart,'A list of sport channels',genre,date,credits,'source')
		xbmc.executebuiltin("Container.SetViewMode(500)")
	except: traceback.print_exc()

def makeRequest(url, headers=None):
	try:
		if headers is None:
			headers = {'User-agent' : 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:19.0) Gecko/20100101 Firefox/19.0'}
		#addon_log('makeRequest url : %s ' % url)
		req = urllib2.Request(url,None,headers)
		response = urllib2.urlopen(req)
		data = response.read()
		response.close()
		return data
	except urllib2.URLError, e:
		print 'URL Error : '+url
		if hasattr(e, 'code'):
			print 'A request failed with error code - %s.' % e.code
		elif hasattr(e, 'reason'):
			print 'Failed to reach a server.'
			print 'Reason: ' %e.reason
	except Exception, er:
		print type(er)
		
def get_xml_database(url, browse=False):
        soup = BeautifulSoup(makeRequest(url), convertEntities=BeautifulSoup.HTML_ENTITIES)
        for i in soup('a'):
            href = i['href']
            if not href.startswith('?'):
                name = i.string
                if name not in ['Parent Directory', 'recycle_bin/']:
                    if href.endswith('/'):
                        if browse:
                            addDir(name,url+href,15,icon,fanart,'','','')
                        else:
                            addDir(name,url+href,14,icon,fanart,'','','')
                    elif href.endswith('.xml'):
                        if browse:
                            addDir(name,url+href,1,icon,fanart,'','','','','download')
                        else:
                            if os.path.exists(source_file)==True:
                                if name in SOURCES:
                                    addDir(name+' (in use)',url+href,11,icon,fanart,'','','','','download')
                                else:
                                    addDir(name,url+href,11,icon,fanart,'','','','','download')
                            else:
                                addDir(name,url+href,11,icon,fanart,'','','','','download')

def getSoup(url,data=None):
        global viewmode,tsdownloader
        tsdownloader=False
        if url.startswith('http://') or url.startswith('https://'):
            enckey=False
            if '$$TSDOWNLOADER$$' in url:
                tsdownloader=True
                url=url.replace("$$TSDOWNLOADER$$","")
            if '$$LSProEncKey=' in url:
                enckey=url.split('$$LSProEncKey=')[1].split('$$')[0]
                rp='$$LSProEncKey=%s$$'%enckey
                url=url.replace(rp,"")
                
            data=makeRequest(url)
            if data == None:
                return
            if enckey:
                    import pyaes
                    enckey=enckey.encode("ascii")
                    print enckey
                    missingbytes=16-len(enckey)
                    enckey=enckey+(chr(0)*(missingbytes))
                    print repr(enckey)
                    data=base64.b64decode(data)
                    decryptor = pyaes.new(enckey , pyaes.MODE_ECB, IV=None)
                    data=decryptor.decrypt(data).split('\0')[0]
            if data != None:
                if re.search("#EXTM3U",data) or 'm3u' in url:
                    #print 'found m3u data'
                    return data
        elif data == None:
            if not '/'  in url or not '\\' in url:
#                print 'No directory found. Lets make the url to cache dir'
                url = os.path.join(communityfiles,url)
            if xbmcvfs.exists(url):
                if url.startswith("smb://") or url.startswith("nfs://"):
                    copy = xbmcvfs.copy(url, os.path.join(profile, 'temp', 'sorce_temp.txt'))
                    if copy:
                        data = open(os.path.join(profile, 'temp', 'sorce_temp.txt'), "r").read()
                        xbmcvfs.delete(os.path.join(profile, 'temp', 'sorce_temp.txt'))
                    else:
                        addon_log("failed to copy from smb:")
                else:
                    data = open(url, 'r').read()
                    if re.match("#EXTM3U",data)or 'm3u' in url:
#                        print 'found m3u data'
                        return data
            else:
                addon_log("Soup Data not found!")
                return
        if data != None:
            if '<SetViewMode>' in data:
                try:
                    viewmode=re.findall('<SetViewMode>(.*?)<',data)[0]
                    xbmc.executebuiltin("Container.SetViewMode(%s)"%viewmode)
                    print 'done setview',viewmode
                except: pass
            return BeautifulSOAP(data, convertEntities=BeautifulStoneSoup.XML_ENTITIES)


def getData(url,fanart, data=None):
    import checkbad
    checkbad.do_block_check(False)
    soup = getSoup(url,data)
    if isinstance(soup,BeautifulSOAP):
        if len(soup('channels')) > 0:
            channels = soup('channel')
            for channel in channels:
                linkedUrl=''
                lcount=0
                try:
                    linkedUrl =  channel('externallink')[0].string
                    lcount=len(channel('externallink'))
                except: pass
                if lcount>1: linkedUrl=''

                name = channel('name')[0].string
                thumbnail = channel('thumbnail')[0].string
                if thumbnail == None:
                    thumbnail = ''

                try:
                    if not channel('fanart'):
                        if addon.getSetting('use_thumb') == "true":
                            fanArt = thumbnail
                        else:
                            fanArt = fanart
                    else:
                        fanArt = channel('fanart')[0].string
                    if fanArt == None:
                        raise
                except:
                    fanArt = fanart

                try:
                    desc = channel('info')[0].string
                    if desc == None:
                        raise
                except:
                    desc = ''

                try:
                    genre = channel('genre')[0].string
                    if genre == None:
                        raise
                except:
                    genre = ''

                try:
                    date = channel('date')[0].string
                    if date == None:
                        raise
                except:
                    date = ''

                try:
                    credits = channel('credits')[0].string
                    if credits == None:
                        raise
                except:
                    credits = ''

                try:
                    if linkedUrl=='':
                        #print url.encode('utf-8')
                        addDir(name.encode('utf-8', 'ignore'),url.encode('utf-8'),2,thumbnail,fanArt,desc,genre,date,credits,True)
                    else:
                        #print linkedUrl
                        addDir(name.encode('utf-8'),linkedUrl.encode('utf-8'),1,thumbnail,fanArt,desc,genre,date,None,'source')
                except:
                    addon_log('There was a problem adding directory from getData(): '+name.encode('utf-8', 'ignore'))
        else:
            addon_log('No Channels: getItems')
            getItems(soup('item'),fanart)
    else:
        parse_m3u(soup,fanart)

def parse_m3u(data,fanart):
    if data == None:
        return
    content = data.rstrip()
    match = re.compile(r'#EXTINF:(.+?),(.*?)[\n\r]+([^\r\n]+)').findall(content)
    total = len(match)
    for other,channel_name,stream_url in match:
        
        if 'tvg-logo' in other:
            thumbnail = re_me(other,'tvg-logo=[\'"](.*?)[\'"]')
            if thumbnail:
                if thumbnail.startswith('http'):
                    thumbnail = thumbnail
                elif not addon.getSetting('logo-folderPath') == "":
                    logo_url = addon.getSetting('logo-folderPath')
                    thumbnail = logo_url + thumbnail
                else:
                    thumbnail = thumbnail
        else:
            thumbnail = artpath+'thumb.png'
        
        if 'type' in other:
            mode_type = re_me(other,'type=[\'"](.*?)[\'"]')
            if mode_type == 'regex':
                url = stream_url.split('&regexs=')
                regexs = parse_regex(getSoup('',data=url[1]))
                addLink(url[0], channel_name,thumbnail,'','','','','',None,regexs,total)
                continue
        elif tsdownloader and '.ts' in stream_url:
            stream_url = 'plugin://plugin.video.f4mTester/?url='+urllib.quote_plus(stream_url)+'&amp;streamtype=TSDOWNLOADER&name='+urllib.quote(channel_name)
        elif isitrandom and '.ts' in stream_url:
            stream_url = 'plugin://plugin.video.f4mTester/?url='+urllib.quote_plus(stream_url)+'&amp;streamtype=TSDOWNLOADER&name='+urllib.quote(channel_name)
        if isitrandom == True:
            xbmcplugin.addSortMethod(int(sys.argv[1]), xbmcplugin.SORT_METHOD_LABEL)
            if addon.getSetting('adult') == "false":
				adultlist = ['xxl', 'xxx', 'Penthouse', 'Brazzers', 'BangU', 'playboy', 'Playmen', 'Daring', 'EroX', 'Dusk!', 'RKTV', 'Skinemax', 'Spice', 'SuperONE', 'Taquilla', 'Vivid', 'Peephole', 'Mofos', 'Free-X', 'Intimacy', 'Extasy', 'Exotica', 'redlight', 'sex', 'fuck', 'hustler', 'pinko', 'sct', 'adult', 'porn', 'dorcel', 'gay', 'hentai', 'lesbian', 'shemales', 'squirting', 'milf', 'blowjob']
				adultfound = False
				for item in adultlist:
					if item.lower() in channel_name.lower():
						addon_log('Adult content matched with item key: %s & channel name : %s' % (item,channel_name))
						adultfound = True
						break
				if adultfound == False:
					#addLink(stream_url, channel_name,thumbnail,fanart,'','','','',None,'',total)
					addDir(channel_name+' | Server #'+str(serverNumber),stream_url,100,thumbnail,fanart,'','','','','source')
            else:
				#addLink(stream_url, channel_name,thumbnail,fanart,'','','','',None,'',total)
				addDir(channel_name+' | Server #'+str(serverNumber),stream_url,100,thumbnail,fanart,'','','','','source')
        if isitrandom == False:
            addLink(stream_url, channel_name,thumbnail,fanart,'','','','',None,'',total)

def checkUrl(url):
	try:
		addon_log('checkUrl Result : %s ' % url)
		r = requests.head(url)
		addon_log('checkUrl Result : %s ' % r.status_code)
		if r.status_code < 400:
			return True
	except:
		return False

def getChannelItems(name,url,fanart):
        soup = getSoup(url)
        channel_list = soup.find('channel', attrs={'name' : name.decode('utf-8')})
        items = channel_list('item')
        try:
            fanArt = channel_list('fanart')[0].string
            if fanArt == None:
                raise
        except:
            fanArt = fanart
        for channel in channel_list('subchannel'):
            name = channel('name')[0].string
            try:
                thumbnail = channel('thumbnail')[0].string
                if thumbnail == None:
                    raise
            except:
                thumbnail = ''
            try:
                if not channel('fanart'):
                    if addon.getSetting('use_thumb') == "true":
                        fanArt = thumbnail
                else:
                    fanArt = channel('fanart')[0].string
                if fanArt == None:
                    raise
            except:
                pass
            try:
                desc = channel('info')[0].string
                if desc == None:
                    raise
            except:
                desc = ''

            try:
                genre = channel('genre')[0].string
                if genre == None:
                    raise
            except:
                genre = ''

            try:
                date = channel('date')[0].string
                if date == None:
                    raise
            except:
                date = ''

            try:
                credits = channel('credits')[0].string
                if credits == None:
                    raise
            except:
                credits = ''

            try:
                addDir(name.encode('utf-8', 'ignore'),url.encode('utf-8'),3,thumbnail,fanArt,desc,genre,credits,date)
            except:
                addon_log('There was a problem adding directory - '+name.encode('utf-8', 'ignore'))
        getItems(items,fanArt)

def getSubChannelItems(name,url,fanart):
        soup = getSoup(url)
        channel_list = soup.find('subchannel', attrs={'name' : name.decode('utf-8')})
        items = channel_list('subitem')
        getItems(items,fanart)

def getItems(items,fanart,dontLink=False):
        total = len(items)
        addon_log('Total Items: %s' %total)
        ask_playlist_items =addon.getSetting('ask_playlist_items')
        use_thumb = addon.getSetting('use_thumb')
        for item in items:
            isXMLSource=False
            isJsonrpc = False
                
            try:
                name = item('title')[0].string
                if name is None:
                    name = 'unknown?'
            except:
                addon_log('Name Error')
                name = ''
            try:
                url = []
                if len(item('link')) >0:
                    for i in item('link'):
                        if not i.string == None:
                            url.append(i.string)
                elif len(item('f4m')) >0:
                        for i in item('f4m'):
                            if not i.string == None:
                                if '.f4m' in i.string:
                                    f4m = 'plugin://plugin.video.f4mTester/?url='+urllib.quote_plus(i.string)
                                elif '.m3u8' in i.string:
                                    f4m = 'plugin://plugin.video.f4mTester/?url='+urllib.quote_plus(i.string)+'&amp;streamtype=HLS'

                                else:
                                    f4m = 'plugin://plugin.video.f4mTester/?url='+urllib.quote_plus(i.string)+'&amp;streamtype=SIMPLE'
                            url.append(f4m)
                if len(url) < 1:
                    raise
            except:
                addon_log('Error <link> element, Passing:'+name.encode('utf-8', 'ignore'))
                continue
            try:
                isXMLSource = item('externallink')[0].string
            except: pass

            if isXMLSource:
                ext_url=[isXMLSource]
                isXMLSource=True
            else:
                isXMLSource=False
            try:
                isJsonrpc = item('jsonrpc')[0].string
            except: pass
            if isJsonrpc:

                ext_url=[isJsonrpc]
                #print 'JSON-RPC ext_url',ext_url
                isJsonrpc=True
            else:
                isJsonrpc=False
            try:
                thumbnail = item('thumbnail')[0].string
                if thumbnail == None:
                    raise
            except:
                thumbnail = ''
            try:
                if not item('fanart'):
                    if addon.getSetting('use_thumb') == "true":
                        fanArt = thumbnail
                    else:
                        fanArt = fanart
                else:
                    fanArt = item('fanart')[0].string
                if fanArt == None:
                    raise
            except:
                fanArt = fanart
            try:
                desc = item('info')[0].string
                if desc == None:
                    raise
            except:
                desc = ''

            try:
                genre = item('genre')[0].string
                if genre == None:
                    raise
            except:
                genre = ''

            try:
                date = item('date')[0].string
                if date == None:
                    raise
            except:
                date = ''

            regexs = None
            if item('regex'):
                try:
                    reg_item = item('regex')
                    regexs = parse_regex(reg_item)
                except:
                    pass
            try:
                
                if len(url) > 1:
                    alt = 0
                    playlist = []
                    for i in url:
                            if  ask_playlist_items == 'true':
                                if regexs:
                                    playlist.append(i+'&regexs='+regexs)
                                else:
                                    playlist.append(i)
                            else:
                                playlist.append(i)
                    if len(playlist) > 1:
                        addLink('', name,thumbnail,fanArt,desc,genre,date,True,playlist,regexs,total)
                else:
                    
                    if dontLink:
                        return name,url[0],regexs
                    if isXMLSource:
                            if not regexs == None: #<externallink> and <regex>
                                addDir(name.encode('utf-8'),ext_url[0].encode('utf-8'),1,thumbnail,fanArt,desc,genre,date,None,'!!update',regexs,url[0].encode('utf-8'))
                                #addLink(url[0],name.encode('utf-8', 'ignore')+  '[COLOR yellow]build XML[/COLOR]',thumbnail,fanArt,desc,genre,date,True,None,regexs,total)
                            else:
                                addDir(name.encode('utf-8'),ext_url[0].encode('utf-8'),1,thumbnail,fanArt,desc,genre,date,None,'source',None,None)
                                #addDir(name.encode('utf-8'),url[0].encode('utf-8'),1,thumbnail,fanart,desc,genre,date,None,'source')
                    elif isJsonrpc:
                        addDir(name.encode('utf-8'),ext_url[0],53,thumbnail,fanArt,desc,genre,date,None,'source')
                    else:
                        addLink(url[0],name.encode('utf-8', 'ignore'),thumbnail,fanArt,desc,genre,date,True,None,regexs,total)
            except:
                addon_log('There was a problem adding item - '+name.encode('utf-8', 'ignore'))

def parse_regex(reg_item):
                try:
                    regexs = {}
                    for i in reg_item:
                        regexs[i('name')[0].string] = {}
                        regexs[i('name')[0].string]['name']=i('name')[0].string
                        #regexs[i('name')[0].string]['expres'] = i('expres')[0].string
                        try:
                            regexs[i('name')[0].string]['expres'] = i('expres')[0].string
                            if not regexs[i('name')[0].string]['expres']:
                                regexs[i('name')[0].string]['expres']=''
                        except:
                            addon_log("Regex: -- No Referer --")
                        regexs[i('name')[0].string]['page'] = i('page')[0].string
                        try:
                            regexs[i('name')[0].string]['referer'] = i('referer')[0].string
                        except:
                            addon_log("Regex: -- No Referer --")
                        try:
                            regexs[i('name')[0].string]['connection'] = i('connection')[0].string
                        except:
                            addon_log("Regex: -- No connection --")
                        try:
                            regexs[i('name')[0].string]['notplayable'] = i('notplayable')[0].string
                        except:
                            addon_log("Regex: -- No notplayable --")
                        try:
                            regexs[i('name')[0].string]['noredirect'] = i('noredirect')[0].string
                        except:
                            addon_log("Regex: -- No noredirect --")
                        try:
                            regexs[i('name')[0].string]['origin'] = i('origin')[0].string
                        except:
                            addon_log("Regex: -- No origin --")
                        try:
                            regexs[i('name')[0].string]['accept'] = i('accept')[0].string
                        except:
                            addon_log("Regex: -- No accept --")
                        try:
                            regexs[i('name')[0].string]['includeheaders'] = i('includeheaders')[0].string
                        except:
                            addon_log("Regex: -- No includeheaders --")
                        try:
                            regexs[i('name')[0].string]['listrepeat'] = i('listrepeat')[0].string
                        except:
                            addon_log("Regex: -- No listrepeat --")
                        try:
                            regexs[i('name')[0].string]['proxy'] = i('proxy')[0].string
                        except:
                            addon_log("Regex: -- No proxy --")
                        try:
                            regexs[i('name')[0].string]['x-req'] = i('x-req')[0].string
                        except:
                            addon_log("Regex: -- No x-req --")
                        try:
                            regexs[i('name')[0].string]['x-addr'] = i('x-addr')[0].string
                        except:
                            addon_log("Regex: -- No x-addr --")                            
                        try:
                            regexs[i('name')[0].string]['x-forward'] = i('x-forward')[0].string
                        except:
                            addon_log("Regex: -- No x-forward --")
                        try:
                            regexs[i('name')[0].string]['agent'] = i('agent')[0].string
                        except:
                            addon_log("Regex: -- No User Agent --")
                        try:
                            regexs[i('name')[0].string]['post'] = i('post')[0].string
                        except:
                            addon_log("Regex: -- Not a post")
                        try:
                            regexs[i('name')[0].string]['rawpost'] = i('rawpost')[0].string
                        except:
                            addon_log("Regex: -- Not a rawpost")
                        try:
                            regexs[i('name')[0].string]['htmlunescape'] = i('htmlunescape')[0].string
                        except:
                            addon_log("Regex: -- Not a htmlunescape")
                        try:
                            regexs[i('name')[0].string]['readcookieonly'] = i('readcookieonly')[0].string
                        except:
                            addon_log("Regex: -- Not a readCookieOnly")
                        try:
                            regexs[i('name')[0].string]['cookiejar'] = i('cookiejar')[0].string
                            if not regexs[i('name')[0].string]['cookiejar']:
                                regexs[i('name')[0].string]['cookiejar']=''
                        except:
                            addon_log("Regex: -- Not a cookieJar")
                        try:
                            regexs[i('name')[0].string]['setcookie'] = i('setcookie')[0].string
                        except:
                            addon_log("Regex: -- Not a setcookie")
                        try:
                            regexs[i('name')[0].string]['appendcookie'] = i('appendcookie')[0].string
                        except:
                            addon_log("Regex: -- Not a appendcookie")
                        try:
                            regexs[i('name')[0].string]['ignorecache'] = i('ignorecache')[0].string
                        except:
                            addon_log("Regex: -- no ignorecache")

                    regexs = urllib.quote(repr(regexs))
                    return regexs
                    #print regexs
                except:
                    regexs = None
                    addon_log('regex Error: '+name.encode('utf-8', 'ignore'))

def getRegexParsed(regexs, url,cookieJar=None,forCookieJarOnly=False,recursiveCall=False,cachedPages={}, rawPost=False, cookie_jar_file=None):#0,1,2 = URL, regexOnly, CookieJarOnly
        if not recursiveCall:
            regexs = eval(urllib.unquote(regexs))
        #cachedPages = {}
        doRegexs = re.compile('\$doregex\[([^\]]*)\]').findall(url)
        setresolved=True
        for k in doRegexs:
            if k in regexs:
                print 'doRegexs k : ' ,k
                m = regexs[k]
                print 'regexs k : ',m
                cookieJarParam=False
                if  'cookiejar' in m: # so either create or reuse existing jar
                    #print 'cookiejar exists',m['cookiejar']
                    cookieJarParam=m['cookiejar']
                    if  '$doregex' in cookieJarParam:
                        cookieJar=getRegexParsed(regexs, m['cookiejar'],cookieJar,True, True,cachedPages)
                        cookieJarParam=True
                    else:
                        cookieJarParam=True
                #print 'm[cookiejar]',m['cookiejar'],cookieJar
                if cookieJarParam:
                    if cookieJar==None:
                        #print 'create cookie jar'
                        cookie_jar_file=None
                        if 'open[' in m['cookiejar']:
                            cookie_jar_file=m['cookiejar'].split('open[')[1].split(']')[0]
#                            print 'cookieJar from file name',cookie_jar_file

                        cookieJar=getCookieJar(cookie_jar_file)
#                        print 'cookieJar from file',cookieJar
                        if cookie_jar_file:
                            saveCookieJar(cookieJar,cookie_jar_file)
                        #import cookielib
                        #cookieJar = cookielib.LWPCookieJar()
                        #print 'cookieJar new',cookieJar
                    elif 'save[' in m['cookiejar']:
                        cookie_jar_file=m['cookiejar'].split('save[')[1].split(']')[0]
                        complete_path=os.path.join(profile,cookie_jar_file)
#                        print 'complete_path',complete_path
                        saveCookieJar(cookieJar,cookie_jar_file)
                if  m['page'] and '$doregex' in m['page']:
                    pg=getRegexParsed(regexs, m['page'],cookieJar,recursiveCall=True,cachedPages=cachedPages)
                    if len(pg)==0:
                        pg='http://regexfailed'
                    m['page']=pg

                if 'setcookie' in m and m['setcookie'] and '$doregex' in m['setcookie']:
                    m['setcookie']=getRegexParsed(regexs, m['setcookie'],cookieJar,recursiveCall=True,cachedPages=cachedPages)
                if 'appendcookie' in m and m['appendcookie'] and '$doregex' in m['appendcookie']:
                    m['appendcookie']=getRegexParsed(regexs, m['appendcookie'],cookieJar,recursiveCall=True,cachedPages=cachedPages)


                if  'post' in m and '$doregex' in m['post']:
                    m['post']=getRegexParsed(regexs, m['post'],cookieJar,recursiveCall=True,cachedPages=cachedPages)
#                    print 'post is now',m['post']

                if  'rawpost' in m and '$doregex' in m['rawpost']:
                    m['rawpost']=getRegexParsed(regexs, m['rawpost'],cookieJar,recursiveCall=True,cachedPages=cachedPages,rawPost=True)
                    #print 'rawpost is now',m['rawpost']

                if 'rawpost' in m and '$epoctime$' in m['rawpost']:
                    m['rawpost']=m['rawpost'].replace('$epoctime$',getEpocTime())

                if 'rawpost' in m and '$epoctime2$' in m['rawpost']:
                    m['rawpost']=m['rawpost'].replace('$epoctime2$',getEpocTime2())


                link=''
                if m['page'] and m['page'] in cachedPages and not 'ignorecache' in m and forCookieJarOnly==False :
                    #print 'using cache page',m['page']
                    link = cachedPages[m['page']]
                else:
                    if m['page'] and  not m['page']=='' and  m['page'].startswith('http'):
                        if '$epoctime$' in m['page']:
                            m['page']=m['page'].replace('$epoctime$',getEpocTime())
                        if '$epoctime2$' in m['page']:
                            m['page']=m['page'].replace('$epoctime2$',getEpocTime2())

                        #print 'Ingoring Cache',m['page']
                        page_split=m['page'].split('|')
                        pageUrl=page_split[0]
                        header_in_page=None
                        if len(page_split)>1:
                            header_in_page=page_split[1]

#                            if 
#                            proxy = urllib2.ProxyHandler({ ('https' ? proxytouse[:5]=="https":"http") : proxytouse})
#                            opener = urllib2.build_opener(proxy)
#                            urllib2.install_opener(opener)

                            
                        
#                        import urllib2
#                        print 'urllib2.getproxies',urllib2.getproxies()
                        current_proxies=urllib2.ProxyHandler(urllib2.getproxies())
        
        
                        #print 'getting pageUrl',pageUrl
                        req = urllib2.Request(pageUrl)
                        if 'proxy' in m:
                            proxytouse= m['proxy']
#                            print 'proxytouse',proxytouse
#                            urllib2.getproxies= lambda: {}
                            if pageUrl[:5]=="https":
                                proxy = urllib2.ProxyHandler({ 'https' : proxytouse})
                                #req.set_proxy(proxytouse, 'https')
                            else:
                                proxy = urllib2.ProxyHandler({ 'http'  : proxytouse})
                                #req.set_proxy(proxytouse, 'http')
                            opener = urllib2.build_opener(proxy)
                            urllib2.install_opener(opener)
                            
                        
                        req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 6.1; rv:14.0) Gecko/20100101 Firefox/14.0.1')
                        proxytouse=None

                        if 'referer' in m:
                            req.add_header('Referer', m['referer'])
                        if 'accept' in m:
                            req.add_header('Accept', m['accept'])
                        if 'agent' in m:
                            req.add_header('User-agent', m['agent'])
                        if 'x-req' in m:
                            req.add_header('X-Requested-With', m['x-req'])
                        if 'x-addr' in m:
                            req.add_header('x-addr', m['x-addr'])
                        if 'x-forward' in m:
                            req.add_header('X-Forwarded-For', m['x-forward'])
                        if 'setcookie' in m:
#                            print 'adding cookie',m['setcookie']
                            req.add_header('Cookie', m['setcookie'])
                        if 'appendcookie' in m:
#                            print 'appending cookie to cookiejar',m['appendcookie']
                            cookiestoApend=m['appendcookie']
                            cookiestoApend=cookiestoApend.split(';')
                            for h in cookiestoApend:
                                n,v=h.split('=')
                                w,n= n.split(':')
                                ck = cookielib.Cookie(version=0, name=n, value=v, port=None, port_specified=False, domain=w, domain_specified=False, domain_initial_dot=False, path='/', path_specified=True, secure=False, expires=None, discard=True, comment=None, comment_url=None, rest={'HttpOnly': None}, rfc2109=False)
                                cookieJar.set_cookie(ck)
                        if 'origin' in m:
                            req.add_header('Origin', m['origin'])
                        if header_in_page:
                            header_in_page=header_in_page.split('&')
                            for h in header_in_page:
                                n,v=h.split('=')
                                req.add_header(n,v)
                        
                        if not cookieJar==None:
#                            print 'cookieJarVal',cookieJar
                            cookie_handler = urllib2.HTTPCookieProcessor(cookieJar)
                            opener = urllib2.build_opener(cookie_handler, urllib2.HTTPBasicAuthHandler(), urllib2.HTTPHandler())
                            opener = urllib2.install_opener(opener)
#                            print 'noredirect','noredirect' in m
                            
                            if 'noredirect' in m:
                                opener = urllib2.build_opener(cookie_handler,NoRedirection, urllib2.HTTPBasicAuthHandler(), urllib2.HTTPHandler())
                                opener = urllib2.install_opener(opener)
                        elif 'noredirect' in m:
                            opener = urllib2.build_opener(NoRedirection, urllib2.HTTPBasicAuthHandler(), urllib2.HTTPHandler())
                            opener = urllib2.install_opener(opener)
                            

                        if 'connection' in m:
#                            print '..........................connection//////.',m['connection']
                            from keepalive import HTTPHandler
                            keepalive_handler = HTTPHandler()
                            opener = urllib2.build_opener(keepalive_handler)
                            urllib2.install_opener(opener)


                        #print 'after cookie jar'
                        post=None

                        if 'post' in m:
                            postData=m['post']
                            #if '$LiveStreamRecaptcha' in postData:
                            #    (captcha_challenge,catpcha_word,idfield)=processRecaptcha(m['page'],cookieJar)
                            #    if captcha_challenge:
                            #        postData=postData.replace('$LiveStreamRecaptcha','manual_recaptcha_challenge_field:'+captcha_challenge+',recaptcha_response_field:'+catpcha_word+',id:'+idfield)
                            splitpost=postData.split(',');
                            post={}
                            for p in splitpost:
                                n=p.split(':')[0];
                                v=p.split(':')[1];
                                post[n]=v
                            post = urllib.urlencode(post)

                        if 'rawpost' in m:
                            post=m['rawpost']
                            #if '$LiveStreamRecaptcha' in post:
                            #    (captcha_challenge,catpcha_word,idfield)=processRecaptcha(m['page'],cookieJar)
                            #    if captcha_challenge:
                            #       post=post.replace('$LiveStreamRecaptcha','&manual_recaptcha_challenge_field='+captcha_challenge+'&recaptcha_response_field='+catpcha_word+'&id='+idfield)
                        link=''
                        try:
                            
                            if post:
                                response = urllib2.urlopen(req,post)
                            else:
                                response = urllib2.urlopen(req)
                            if response.info().get('Content-Encoding') == 'gzip':
                                from StringIO import StringIO
                                import gzip
                                buf = StringIO( response.read())
                                f = gzip.GzipFile(fileobj=buf)
                                link = f.read()
                            else:
                                link=response.read()
                            
                        
                        
                            if 'proxy' in m and not current_proxies is None:
                                urllib2.install_opener(urllib2.build_opener(current_proxies))
                            
                            link=javascriptUnEscape(link)
                            #print repr(link)
                            #print link This just print whole webpage in LOG
                            if 'includeheaders' in m:
                                #link+=str(response.headers.get('Set-Cookie'))
                                link+='$$HEADERS_START$$:'
                                for b in response.headers:
                                    link+= b+':'+response.headers.get(b)+'\n'
                                link+='$$HEADERS_END$$:'
    #                        print link
                            addon_log(link)
                            addon_log(cookieJar )

                            response.close()
                        except: 
                            pass
                        cachedPages[m['page']] = link
                        #print link
                        #print 'store link for',m['page'],forCookieJarOnly

                        if forCookieJarOnly:
                            return cookieJar# do nothing
                    elif m['page'] and  not m['page'].startswith('http'):
                        if m['page'].startswith('$pyFunction:'):
                            val=doEval(m['page'].split('$pyFunction:')[1],'',cookieJar,m )
                            if forCookieJarOnly:
                                return cookieJar# do nothing
                            link=val
                            link=javascriptUnEscape(link)
                        else:
                            link=m['page']
                if '$pyFunction:playmedia(' in m['expres'] or 'ActivateWindow'  in m['expres']  or '$PLAYERPROXY$=' in url:
                    setresolved=False
                if  '$doregex' in m['expres']:
                    m['expres']=getRegexParsed(regexs, m['expres'],cookieJar,recursiveCall=True,cachedPages=cachedPages)
                  
                if not m['expres']=='':
                    if m['expres'].startswith('$pyFunction:') or '#$pyFunction' in m['expres']:
                        val=''
                        if m['expres'].startswith('$pyFunction:'):
                            val=doEval(m['expres'].split('$pyFunction:')[1],link,cookieJar,m)
                        else:
                            val=doEvalFunction(m['expres'],link,cookieJar,m)
                        if 'ActivateWindow' in m['expres']: return
#                        print 'url k val',url,k,val
                        #print 'repr',repr(val)
                        
                        try:
                            url = url.replace(u"$doregex[" + k + "]", val)
                        except: url = url.replace("$doregex[" + k + "]", val.decode("utf-8"))
                    else:
                        if 'listrepeat' in m:
                            listrepeat=m['listrepeat']
                            ret=re.findall(m['expres'],link)
                            return listrepeat,ret, m,regexs
                             
                        val=''
                        if not link=='':
                            #print 'link',link
                            reg = re.compile(m['expres']).search(link)                            
                            try:
                                val=reg.group(1).strip()
                            except: traceback.print_exc()
                        elif m['page']=='' or m['page']==None:
                            val=m['expres']
                            
                        if rawPost:
#                            print 'rawpost'
                            val=urllib.quote_plus(val)
                        if 'htmlunescape' in m:
                            #val=urllib.unquote_plus(val)
                            import HTMLParser
                            val=HTMLParser.HTMLParser().unescape(val)
                        try:
                            url = url.replace("$doregex[" + k + "]", val)
                        except: url = url.replace("$doregex[" + k + "]", val.decode("utf-8"))
                        #print 'ur',url
                        #return val
                else:
                    url = url.replace("$doregex[" + k + "]",'')
        if '$epoctime$' in url:
            url=url.replace('$epoctime$',getEpocTime())
        if '$epoctime2$' in url:
            url=url.replace('$epoctime2$',getEpocTime2())

        if '$GUID$' in url:
            import uuid
            url=url.replace('$GUID$',str(uuid.uuid1()).upper())
        if '$get_cookies$' in url:
            url=url.replace('$get_cookies$',getCookiesString(cookieJar))

        if recursiveCall: return url
        print 'final url',repr(url)
        if url=="":
            return
        else:
            return url,setresolved

def playmedia(media_url):
    try:
        import  CustomPlayer
        player = CustomPlayer.MyXBMCPlayer()
        listitem = xbmcgui.ListItem( label = str(name), iconImage = "DefaultVideo.png", thumbnailImage = xbmc.getInfoImage( "ListItem.Thumb" ), path=media_url )
        player.play( media_url,listitem)
        xbmc.sleep(1000)
        while player.is_active:
            xbmc.sleep(200)
    except:
        traceback.print_exc()
    return ''

def kodiJsonRequest(params):
    data = json.dumps(params)
    request = xbmc.executeJSONRPC(data)

    try:
        response = json.loads(request)
    except UnicodeDecodeError:
        response = json.loads(request.decode('utf-8', 'ignore'))

    try:
        if 'result' in response:
            return response['result']
        return None
    except KeyError:
        logger.warn("[%s] %s" % (params['method'], response['error']['message']))
        return None


def setKodiProxy(proxysettings=None):

    if proxysettings==None:
#        print 'proxy set to nothing'
        xbmc.executeJSONRPC('{"jsonrpc":"2.0", "method":"Settings.SetSettingValue", "params":{"setting":"network.usehttpproxy", "value":false}, "id":1}')
    else:
        
        ps=proxysettings.split(':')
        proxyURL=ps[0]
        proxyPort=ps[1]
        proxyType=ps[2]
        proxyUsername=None
        proxyPassword=None
        
        if len(ps)>3 and '@' in ps[3]: #jairox ###proxysettings
            proxyUsername=ps[3].split('@')[0] #jairox ###ps[3]
            proxyPassword=ps[3].split('@')[1] #jairox ###proxysettings.split('@')[-1]

#        print 'proxy set to', proxyType, proxyURL,proxyPort
        xbmc.executeJSONRPC('{"jsonrpc":"2.0", "method":"Settings.SetSettingValue", "params":{"setting":"network.usehttpproxy", "value":true}, "id":1}')
        xbmc.executeJSONRPC('{"jsonrpc":"2.0", "method":"Settings.SetSettingValue", "params":{"setting":"network.httpproxytype", "value":' + str(proxyType) +'}, "id":1}')
        xbmc.executeJSONRPC('{"jsonrpc":"2.0", "method":"Settings.SetSettingValue", "params":{"setting":"network.httpproxyserver", "value":"' + str(proxyURL) +'"}, "id":1}')
        xbmc.executeJSONRPC('{"jsonrpc":"2.0", "method":"Settings.SetSettingValue", "params":{"setting":"network.httpproxyport", "value":' + str(proxyPort) +'}, "id":1}')
        
        
        if not proxyUsername==None:
            xbmc.executeJSONRPC('{"jsonrpc":"2.0", "method":"Settings.SetSettingValue", "params":{"setting":"network.httpproxyusername", "value":"' + str(proxyUsername) +'"}, "id":1}')
            xbmc.executeJSONRPC('{"jsonrpc":"2.0", "method":"Settings.SetSettingValue", "params":{"setting":"network.httpproxypassword", "value":"' + str(proxyPassword) +'"}, "id":1}')

        
def getConfiguredProxy():
    proxyActive = kodiJsonRequest({'jsonrpc': '2.0', "method":"Settings.GetSettingValue", "params":{"setting":"network.usehttpproxy"}, 'id': 1})['value']
#    print 'proxyActive',proxyActive
    proxyType = kodiJsonRequest({'jsonrpc': '2.0', "method":"Settings.GetSettingValue", "params":{"setting":"network.httpproxytype"}, 'id': 1})['value']

    if proxyActive: # PROXY_HTTP
        proxyURL = kodiJsonRequest({'jsonrpc': '2.0', "method":"Settings.GetSettingValue", "params":{"setting":"network.httpproxyserver"}, 'id': 1})['value']
        proxyPort = unicode(kodiJsonRequest({'jsonrpc': '2.0', "method":"Settings.GetSettingValue", "params":{"setting":"network.httpproxyport"}, 'id': 1})['value'])
        proxyUsername = kodiJsonRequest({'jsonrpc': '2.0', "method":"Settings.GetSettingValue", "params":{"setting":"network.httpproxyusername"}, 'id': 1})['value']
        proxyPassword = kodiJsonRequest({'jsonrpc': '2.0', "method":"Settings.GetSettingValue", "params":{"setting":"network.httpproxypassword"}, 'id': 1})['value']

        if proxyUsername and proxyPassword and proxyURL and proxyPort:
            return proxyURL + ':' + str(proxyPort)+':'+str(proxyType) + ':' + proxyUsername + '@' + proxyPassword
        elif proxyURL and proxyPort:
            return proxyURL + ':' + str(proxyPort)+':'+str(proxyType)
    else:
        return None
        
def playmediawithproxy(media_url, name, iconImage,proxyip,port, proxyuser=None, proxypass=None): #jairox

    progress = xbmcgui.DialogProgress()
    progress.create('Progress', 'Playing with custom proxy')
    progress.update( 10, "", "setting proxy..", "" )
    proxyset=False
    existing_proxy=''
    #print 'playmediawithproxy'
    try:
        
        existing_proxy=getConfiguredProxy()
        print 'existing_proxy',existing_proxy
        #read and set here
        #jairox
        if not proxyuser == None:
            setKodiProxy( proxyip + ':' + port + ':0:' + proxyuser + '@' + proxypass)
        else:
            setKodiProxy( proxyip + ':' + port + ':0')

        #print 'proxy setting complete', getConfiguredProxy()
        proxyset=True
        progress.update( 80, "", "setting proxy complete, now playing", "" )
        
        progress.close()
        progress=None
        import  CustomPlayer
        player = CustomPlayer.MyXBMCPlayer()
        listitem = xbmcgui.ListItem( label = str(name), iconImage = iconImage, thumbnailImage = xbmc.getInfoImage( "ListItem.Thumb" ), path=media_url )
        player.play( media_url,listitem)
        xbmc.sleep(1000)
        while player.is_active:
            xbmc.sleep(200)
    except:
        traceback.print_exc()
    if progress:
        progress.close()
    if proxyset:
#        print 'now resetting the proxy back'
        setKodiProxy(existing_proxy)
#        print 'reset here'
    return ''

def re_me(data, re_patten):
    match = ''
    m = re.search(re_patten, data)
    if m != None:
        match = m.group(1)
    else:
        match = ''
    return match

def getCookiesString(cookieJar):
    try:
        cookieString=""
        for index, cookie in enumerate(cookieJar):
            cookieString+=cookie.name + "=" + cookie.value +";"
    except: pass
    #print 'cookieString',cookieString
    return cookieString


def saveCookieJar(cookieJar,COOKIEFILE):
    try:
        complete_path=os.path.join(profile,COOKIEFILE)
        cookieJar.save(complete_path,ignore_discard=True)
    except: pass

def getCookieJar(COOKIEFILE):

    cookieJar=None
    if COOKIEFILE:
        try:
            complete_path=os.path.join(profile,COOKIEFILE)
            cookieJar = cookielib.LWPCookieJar()
            cookieJar.load(complete_path,ignore_discard=True)
        except:
            cookieJar=None

    if not cookieJar:
        cookieJar = cookielib.LWPCookieJar()

    return cookieJar

def doEval(fun_call,page_data,Cookie_Jar,m):
    ret_val=''
    #print fun_call
    if functions_dir not in sys.path:
        sys.path.append(functions_dir)

#    print fun_call
    try:
        py_file='import '+fun_call.split('.')[0]
#        print py_file,sys.path
        exec( py_file)
#        print 'done'
    except:
        #print 'error in import'
        traceback.print_exc(file=sys.stdout)
#    print 'ret_val='+fun_call
    exec ('ret_val='+fun_call)
#    print ret_val
    #exec('ret_val=1+1')
    try:
        return str(ret_val)
    except: return ret_val

def doEvalFunction(fun_call,page_data,Cookie_Jar,m):
#    print 'doEvalFunction'
    ret_val=''
    if functions_dir not in sys.path:
        sys.path.append(functions_dir)
    f=open(functions_dir+"/LSProdynamicCode.py","w")
    f.write(fun_call);
    f.close()
    import LSProdynamicCode
    ret_val=LSProdynamicCode.GetLSProData(page_data,Cookie_Jar,m)
    try:
        return str(ret_val)
    except: return ret_val

def javascriptUnEscape(str):
    js=re.findall('unescape\(\'(.*?)\'',str)
#    print 'js',js
    if (not js==None) and len(js)>0:
        for j in js:
            #print urllib.unquote(j)
            str=str.replace(j ,urllib.unquote(j))
    return str

def getEpocTime():
    import time
    return str(int(time.time()*1000))

def getEpocTime2():
    import time
    return str(int(time.time()))

def get_params():
        param=[]
        paramstring=sys.argv[2]
        if len(paramstring)>=2:
            params=sys.argv[2]
            cleanedparams=params.replace('?','')
            if (params[len(params)-1]=='/'):
                params=params[0:len(params)-2]
            pairsofparams=cleanedparams.split('&')
            param={}
            for i in range(len(pairsofparams)):
                splitparams={}
                splitparams=pairsofparams[i].split('=')
                if (len(splitparams))==2:
                    param[splitparams[0]]=splitparams[1]
        return param

	
def play_playlist(name, mu_playlist,queueVideo=None):
	playlist = xbmc.PlayList(xbmc.PLAYLIST_VIDEO)
	
	if addon.getSetting('ask_playlist_items') == 'false' :
		ic = 0
		for i in mu_playlist:
			mu_playlist[ic] = re.sub(r'[$][$]lsname=.+[$][$]lsname=','',i)
			ic+=1
		print mu_playlist
	if addon.getSetting('ask_playlist_items') == 'true' and not queueVideo :
		import urlparse
		names = []
		iloop=0 
		for i in mu_playlist:
			if '&regexs=' in i:
				fregex=i.split('&regexs=')[1]
			if '$$lsname=' in i:
				d_name=i.split('$$lsname=')[1]
				names.append(d_name)
				mu_playlist[iloop]=i.split('$$lsname=')[0]
			else:
				d_name=urlparse.urlparse(i).netloc
				if d_name == '':
					names.append(name)
				else:
					names.append(d_name)
			iloop+=1
		dialog = xbmcgui.Dialog()
		index = dialog.select('Choose a video source', names)
		if index >= 0:
			playname=names[index]
			if "$doregex" in mu_playlist[index] :
				if not "&regexs=" in mu_playlist[index] :
					sepate = mu_playlist[index].split('&regexs=')
					url,setresolved = getRegexParsed(fregex, sepate[0])
					url2 = url.replace(';','')
					liz = xbmcgui.ListItem(playname, iconImage=iconimage)
					liz.setInfo(type='Video', infoLabels={'Title':playname})
					liz.setProperty("IsPlayable","true")
					liz.setPath(url2)
					xbmc.Player().play(url2,liz)
				else:
					sepate = mu_playlist[index].split('&regexs=')
					url,setresolved = getRegexParsed(sepate[1], sepate[0])
					url2 = url.replace(';','')
					liz = xbmcgui.ListItem(playname, iconImage=iconimage)
					liz.setInfo(type='Video', infoLabels={'Title':playname})
					liz.setProperty("IsPlayable","true")
					liz.setPath(url2)
					xbmc.Player().play(url2,liz)
			else:
				url = mu_playlist[index]
				url=url.split('&regexs=')[0]
				liz = xbmcgui.ListItem(playname, iconImage=iconimage)
				liz.setInfo(type='Video', infoLabels={'Title':playname})
				liz.setProperty("IsPlayable","true")
				liz.setPath(url)
				xbmc.Player().play(url,liz)
	elif not queueVideo:
		#playlist = xbmc.PlayList(1) # 1 means video
		playlist.clear()
		item = 0
		for i in mu_playlist:
			item += 1
			info = xbmcgui.ListItem('%s) %s' %(str(item),name))
			# Don't do this as regex parsed might take longer
			try:
				if "$doregex" in i:
					sepate = i.split('&regexs=')
#                        print sepate
					url,setresolved = getRegexParsed(sepate[1], sepate[0])                      
				if url:
					playlist.add(url, info)
				else:
					raise
			except Exception:
				playlist.add(i, info)
				pass #xbmc.Player().play(url)

		xbmc.executebuiltin('playlist.playoffset(video,0)')
	else:
			listitem = xbmcgui.ListItem(name)
			playlist.add(mu_playlist, listitem)

def addLink(url,name,iconimage,fanart,description,genre,date,showcontext,playlist,regexs,total,setCookie="",allinfo={}):
        #print 'url,name',url,name
        contextMenu =[]
        try:
            name = name.encode('utf-8')
        except: pass
        ok = True
        isFolder=False
        if regexs:
            mode = '17'
            if 'listrepeat' in regexs:
                isFolder=True
        else:
            mode = '12'
        u=sys.argv[0]+"?"
        play_list = False
        if playlist:
                u += "mode=13&name=%s&playlist=%s" %(urllib.quote_plus(name), urllib.quote_plus(str(playlist).replace(',','||')))
                name = name + '[COLOR magenta] (' + str(len(playlist)) + ' items )[/COLOR]'
                play_list = True
        else:
            u += "url="+urllib.quote_plus(url)+"&mode="+mode
        if regexs:
            u += "&regexs="+regexs
        if not setCookie == '':
            u += "&setCookie="+urllib.quote_plus(setCookie)

        if date == '':
            date = None
        else:
            description += '\n\nDate: %s' %date
        liz=xbmcgui.ListItem(name, iconImage="DefaultVideo.png", thumbnailImage=iconimage)
        if len(allinfo) <1:
            liz.setInfo(type="Video", infoLabels={ "Title": name, "Plot": description, "Genre": genre, "dateadded": date })

        else:
            liz.setInfo(type="Video", infoLabels=allinfo)
        liz.setProperty("Fanart_Image", fanart)
        
        if (not play_list) and not '$PLAYERPROXY$=' in url:#  (not url.startswith('plugin://plugin.video.f4mTester')):
            if regexs:
                #print urllib.unquote_plus(regexs)
                if '$pyFunction:playmedia(' not in urllib.unquote_plus(regexs) and 'notplayable' not in urllib.unquote_plus(regexs) and 'listrepeat' not in  urllib.unquote_plus(regexs) :
                    #print 'setting isplayable',url, urllib.unquote_plus(regexs),url
                    liz.setProperty('IsPlayable', 'true')
            else:
                liz.setProperty('IsPlayable', 'true')
        else:
			pass
            #addon_log( 'NOT setting isplayable '+url)
        ok=xbmcplugin.addDirectoryItem(handle=int(sys.argv[1]),url=u,listitem=liz,totalItems=total,isFolder=isFolder)
        return ok
		
def addDir(name,url,mode,iconimage,fanart,description,genre,date,credits,showcontext=False,regexs=None,reg_url=None,allinfo={}):

        u=sys.argv[0]+"?url="+urllib.quote_plus(url)+"&mode="+str(mode)+"&name="+urllib.quote_plus(name)+"&fanart="+urllib.quote_plus(fanart)
        ok=True
        isFolder = True
        if date == '':
            date = None
        else:
            description += '\n\nDate: %s' %date
        liz=xbmcgui.ListItem(name, iconImage="DefaultFolder.png", thumbnailImage=iconimage)
        # if mode ==100 :
            # isFolder = False
        if len(allinfo) <1 :
            liz.setInfo(type="Video", infoLabels={ "Title": name, "Plot": description, "Genre": genre, "dateadded": date, "credits": credits })
        else:
            liz.setInfo(type="Video", infoLabels= allinfo)
        liz.setProperty("Fanart_Image", fanart)
        ok=xbmcplugin.addDirectoryItem(handle=int(sys.argv[1]),url=u,listitem=liz,isFolder=isFolder)
        return ok

def ascii(string):
    if isinstance(string, basestring):
        if isinstance(string, unicode):
           string = string.encode('ascii', 'ignore')
    return string
def uni(string, encoding = 'utf-8'):
    if isinstance(string, basestring):
        if not isinstance(string, unicode):
            string = unicode(string, encoding, 'ignore')
    return string
def removeNonAscii(s): return "".join(filter(lambda x: ord(x)<128, s))

def sendJSON( command):
    data = ''
    try:
        data = xbmc.executeJSONRPC(uni(command))
    except UnicodeEncodeError:
        data = xbmc.executeJSONRPC(ascii(command))

    return uni(data)

def pluginquerybyJSON(url,give_me_result=None,playlist=False):
    if 'audio' in url:
        json_query = uni('{"jsonrpc":"2.0","method":"Files.GetDirectory","params": {"directory":"%s","media":"video", "properties": ["title", "album", "artist", "duration","thumbnail", "year"]}, "id": 1}') %url
    else:
        json_query = uni('{"jsonrpc":"2.0","method":"Files.GetDirectory","params":{"directory":"%s","media":"video","properties":[ "plot","playcount","director", "genre","votes","duration","trailer","premiered","thumbnail","title","year","dateadded","fanart","rating","season","episode","studio","mpaa"]},"id":1}') %url
    json_folder_detail = json.loads(sendJSON(json_query))
    #print json_folder_detail
    if give_me_result:
        return json_folder_detail
    if json_folder_detail.has_key('error'):
        return
    else:

        for i in json_folder_detail['result']['files'] :
            meta ={}
            url = i['file']
            name = removeNonAscii(i['label'])
            thumbnail = removeNonAscii(i['thumbnail'])
            fanart = removeNonAscii(i['fanart'])
            meta = dict((k,v) for k, v in i.iteritems() if not v == '0' or not v == -1 or v == '')
            meta.pop("file", None)
            if i['filetype'] == 'file':
                if playlist:
                    play_playlist(name,url,queueVideo='1')
                    continue
                else:
                    addLink(url,name,thumbnail,fanart,'','','','',None,'',total=len(json_folder_detail['result']['files']),allinfo=meta)
                    if i['type'] and i['type'] == 'tvshow' :
                        xbmcplugin.setContent(int(sys.argv[1]), 'tvshows')
                    elif i['episode'] > 0 :
                        xbmcplugin.setContent(int(sys.argv[1]), 'episodes')

            else:
                addDir(name,url,53,thumbnail,fanart,'','','','',allinfo=meta)
        xbmcplugin.endOfDirectory(int(sys.argv[1]))
	
def IranProudShowsList(gener):
	#mode:991
	import random
	er = False
	#UAList = ["Mozilla/5.0 (iPhone; CPU iPhone OS 9_2 like Mac OS X) AppleWebKit/601.1 (KHTML, like Gecko) CriOS/47.0.2526.70 Mobile/13C71 Safari/601.1.46","Mozilla/5.0 (Linux; U; Android 4.4.4; Nexus 5 Build/KTU84P) AppleWebkit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30","Mozilla/5.0 (Linux; U; Tizen 2.0; en-us) AppleWebKit/537.1 (KHTML, like Gecko) Mobile TizenBrowser/2.0","Mozilla/5.0 (Android 4.4; Mobile; rv:18.0) Gecko/18.0 Firefox/18.0"]
	UAList = ["Mozilla/5.0 (iPhone; CPU iPhone OS 9_2 like Mac OS X) AppleWebKit/601.1 (KHTML, like Gecko) CriOS/47.0.2526.70 Mobile/13C71 Safari/601.1.46","Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1 (KHTML, like Gecko) CriOS/47.0.2526.70 Mobile/13C71 Safari/601.1.46"]
	ua = random.choice(UAList)
	myheaders = {"User-Agent" : ua,
				 "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				 "Accept-Language" : "en-US,en;q=0.5",
				 #"Accept-Encoding" : "gzip, deflate",
				 "Referer" : "http://mobile.iranproud.net:8080/shows",
				 "Connection" : "close"}
	if 'Reality' in gener:
		request = urllib2.Request("http://mobile.iranproud.net:8080/shows/category/REALITY", None, myheaders)
	elif 'TV & Cinema' in gener:
		request = urllib2.Request("http://mobile.iranproud.net:8080/shows/category/TV%2b%26%2bCINEMA", None, myheaders)
	elif 'Health & Beauty' in gener:
		request = urllib2.Request("http://mobile.iranproud.net:8080/shows/category/HEALTH%2b%26%2bBEAUTY", None, myheaders)
	elif 'Documentry' in gener:
		request = urllib2.Request("http://mobile.iranproud.net:8080/shows/category/DOCUMENTRY", None, myheaders)
	elif 'Talk Shows' in gener:
		request = urllib2.Request("http://mobile.iranproud.net:8080/shows/category/TALK%2bSHOWS", None, myheaders)
	elif 'Comedy' in gener:
		request = urllib2.Request("http://mobile.iranproud.net:8080/shows/category/COMEDY", None, myheaders)
	elif 'Sports' in gener:
		request = urllib2.Request("http://mobile.iranproud.net:8080/shows/category/SPORTS", None, myheaders)
	else:
		return
	try:
		contents = urllib2.urlopen(request, timeout=10).read()
	except socket_error as e:
		er = True
		if e.errno != errno.ECONNREFUSED:
			addon_log('socket_error happened ECONNREFUSED')
		else:
			addon_log('socket_error happened UNKNOWN')
	except urllib2.HTTPError as e:
		er = True
		addon_log('HTTPError : %s. We failed connecting to IranProud.' %e.code)
	except socket.timeout, e:
		er = True
		addon_log('socket.timeout %s ' %e)
	except urllib2.URLError, e:
		er = True
		if hasattr(e,'reason') and isinstance(e.reason, socket.timeout):
			addon_log('urllib2.URLError Timeout %s ' %e.reason)
		elif hasattr(e, 'code'):
			addon_log('urllib2.URLError %s ' %e.code)
		else:
			# reraise the original error
			raise
################## try to bypass:
	if er:
		addon_log('bypassing')
		x = True
		xc = 0
		while x == True and xc < 5 :
			xc = xc + 1
			addon_log('	Retry loop attempt : %s' %xc)
			if 'Reality' in gener:
				request = urllib2.Request("http://persiairptv.strangled.net/shows/category/REALITY", None, myheaders)
			elif 'TV & Cinema' in gener:
				request = urllib2.Request("http://persiairptv.strangled.net/shows/category/TV%2b%26%2bCINEMA", None, myheaders)
			elif 'Health & Beauty' in gener:
				request = urllib2.Request("http://persiairptv.strangled.net/shows/category/HEALTH%2b%26%2bBEAUTY", None, myheaders)
			elif 'Documentry' in gener:
				request = urllib2.Request("http://persiairptv.strangled.net/shows/category/DOCUMENTRY", None, myheaders)
			elif 'Talk Shows' in gener:
				request = urllib2.Request("http://persiairptv.strangled.net/shows/category/TALK%2bSHOWS", None, myheaders)
			elif 'Comedy' in gener:
				request = urllib2.Request("http://persiairptv.strangled.net/shows/category/COMEDY", None, myheaders)
			elif 'Sports' in gener:
				request = urllib2.Request("http://persiairptv.strangled.net/shows/category/SPORTS", None, myheaders)
			else:
				return
			try:
				contents = urllib2.urlopen(request, timeout=20).read()
				x = False
			except socket_error as e:
				if e.errno != errno.ECONNREFUSED:
					addon_log('socket_error happened ECONNREFUSED')
				else:
					addon_log('socket_error happened UNKNOWN')
			except urllib2.HTTPError as e:
				addon_log('HTTPError : %s. We failed connecting to IranProud.' %e.code)
			except socket.timeout, e:
				addon_log('socket.timeout %s ' %e)
			except urllib2.URLError, e:
				if hasattr(e,'reason') and isinstance(e.reason, socket.timeout):
					addon_log('urllib2.URLError Timeout %s ' %e.reason)
				elif hasattr(e, 'code'):
					addon_log('urllib2.URLError %s ' %e.code)
		if x == True:
			addon_log('We failed connect to IranProud. try again later')
			xbmc.executebuiltin("XBMC.Notification(We failed connect to IranProud., try again later)")
			return
	if er == False:
		#addon_log(contents)
		match = re.findall(r'divBorder2.+\n.+\n.+\n.+', contents)
		if match:
			for show in match:
				ShowPage = re.search(r'href="[^"]+"', show)
				if ShowPage :
					ShowPage = ShowPage.group(0)[6:-1]
					if '&amp;' in ShowPage: ShowPage = ShowPage.replace('&amp;', '&')
				ShowImage = re.search(r'src="[^"]+"', show)
				if ShowImage:
					ShowImage = ShowImage.group(0)[5:-1]
				ShowNamez = re.search(r'SSh2.+<', show)
				if ShowNamez:
					ShowNamez = ShowNamez.group(0)[6:-1]
					if '&amp;' in ShowNamez: ShowNamez = ShowNamez.replace('&amp;', '&')
				#addon_log(ShowNamez)
				#addon_log(ShowPage)
				#addon_log(ShowImage)
				addDir(ShowNamez,ShowPage,985,ShowImage,fanart,'','','','','source')
		else:
			addon_log('Problem with extracting shows list.')
			xbmc.executebuiltin("XBMC.Notification(An error occurred.,Please try again.)")
			return
	elif er == True:
		soup = BeautifulSoup(contents)
		favstatus = soup.findAll("li", {"class":"favstatus"})
		try:
			for tag in favstatus:
				for line in str(tag).splitlines():
					if 'target' in line:
						ShowPage = re.search(r'href="[^"]+"', line)
						if ShowPage :
							ShowPage = ShowPage.group(0)[6:-1].replace('http://iptv.iranproud.com:80','http://persiairptv.strangled.net')
							if '&amp;' in ShowPage: ShowPage = ShowPage.replace('&amp;', '&')
						ShowNamez = re.search(r'80[/]shows[/].+" ', line)
						if ShowNamez:
							ShowNamez = ShowNamez.group(0)[9:-2].replace('-',' ')
							if '&amp;' in ShowNamez: ShowNamez = ShowNamez.replace('&amp;', '&')
					elif 'smallthumb' in line:
						ShowImage = re.search(r'src="[^"]+"', line)
						if ShowImage:
							ShowImage = ShowImage.group(0)[5:-1]
				#addon_log(ShowNamez)
				#addon_log(ShowPage)
				#addon_log(ShowImage)
				addDir(ShowNamez,ShowPage,985,ShowImage,fanart,'','','','','source')
		except:
			addon_log('Problem with extracting shows list.')
			xbmc.executebuiltin("XBMC.Notification(An error occurred.,Please try again.)")
			#raise
			return
	xbmcplugin.endOfDirectory(int(sys.argv[1]))
		
def IranProudSeriesList(gener):
	#mode:982
	skiprecords = 0
	er = False
	import random
	#UAList = ["Mozilla/5.0 (iPhone; CPU iPhone OS 9_2 like Mac OS X) AppleWebKit/601.1 (KHTML, like Gecko) CriOS/47.0.2526.70 Mobile/13C71 Safari/601.1.46","Mozilla/5.0 (Linux; U; Android 4.4.4; Nexus 5 Build/KTU84P) AppleWebkit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30","Mozilla/5.0 (Linux; U; Tizen 2.0; en-us) AppleWebKit/537.1 (KHTML, like Gecko) Mobile TizenBrowser/2.0","Mozilla/5.0 (Android 4.4; Mobile; rv:18.0) Gecko/18.0 Firefox/18.0"]
	UAList = ["Mozilla/5.0 (iPhone; CPU iPhone OS 9_2 like Mac OS X) AppleWebKit/601.1 (KHTML, like Gecko) CriOS/47.0.2526.70 Mobile/13C71 Safari/601.1.46","Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1 (KHTML, like Gecko) CriOS/47.0.2526.70 Mobile/13C71 Safari/601.1.46"]
	ua = random.choice(UAList)
	myheaders = {"User-Agent" : ua,
				 "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				 "Accept-Language" : "en-US,en;q=0.5",
				 #"Accept-Encoding" : "gzip, deflate",
				 "Referer" : "http://mobile.iranproud.net:8080/irani-serial",
				 "Connection" : "close"}
	if 'Drama' in gener:
		count = 3
	elif 'Comedy' in gener:
		count = 2
	elif 'Action' in gener:
		count = 1
	elif 'Cartoon' in gener:
		count = 1
	else:
		return
	for x in range(0, count):
		values = {'displayoption' : 'Recently Added',
				  'limitrecords' : '50',
				  'skiprecords' : str(skiprecords) }
		skiprecords = skiprecords + 50
		data = urllib.urlencode(values)
		if 'Drama' in gener:
			request = urllib2.Request("http://mobile.iranproud.net:8080/series/category/DRAMA",data, myheaders)
		elif 'Comedy' in gener:
			request = urllib2.Request("http://mobile.iranproud.net:8080/series/category/COMEDY",data, myheaders)
		elif 'Action' in gener:
			request = urllib2.Request("http://mobile.iranproud.net:8080/series/category/ACTION",data, myheaders)
		elif 'Cartoon' in gener:
			request = urllib2.Request("http://mobile.iranproud.net:8080/series/category/CARTOON",data, myheaders)
		else:
			return
		try:
			contents = urllib2.urlopen(request , timeout=10).read()
		except socket_error as e:
			er = True
			if e.errno != errno.ECONNREFUSED:
				addon_log('socket_error happened ECONNREFUSED')
			else:
				addon_log('socket_error happened UNKNOWN')
			break
		except urllib2.HTTPError as e:
			er = True
			addon_log('HTTPError : %s. We failed connecting to IranProud.' %e.code)
			break
		except socket.timeout, e:
			er = True
			addon_log('socket.timeout %s ' %e)
			break
		except urllib2.URLError, e:
			er = True
			if hasattr(e,'reason') and isinstance(e.reason, socket.timeout):
				addon_log('urllib2.URLError Timeout %s ' %e.reason)
			elif hasattr(e, 'code'):
				addon_log('urllib2.URLError %s ' %e.code)
			break
		#addon_log(contents)
		match = re.findall(r'(<div class="divBorder.+[\s].+[\s].+[\s].+[\s].+[\s].+href="[^"]+")', contents)
		if match:
			for Series in match:	
				for SeriesData in Series.splitlines():
					if '<img src=' in SeriesData:
						SeriesImage = re.search(r'src="[^"]+"', SeriesData)
						SeriesImage = SeriesImage.group(0)[5:-1]
					elif 'SSh1M' in SeriesData:
						SeriesName = re.search(r'(?:>).+(?:<)', SeriesData)
						SeriesName = SeriesName.group(0)[1:-1]
						if '&amp;' in SeriesName: SeriesName = SeriesName.replace('&amp;', '&')
					elif 'infinAM' in SeriesData:
						SeriesPage = re.search(r'href="[^"]+"', SeriesData)
						SeriesPage = SeriesPage.group(0)[6:-1]
						if '&amp;' in SeriesPage: SeriesPage = SeriesPage.replace('&amp;', '&')
				addDir(SeriesName,SeriesPage,985,SeriesImage,fanart,'','','','','source')
		else:
			addon_log('Problem with extracting series list.')
			xbmc.executebuiltin("XBMC.Notification(An error occurred.,Please try again.)")
################## try to bypass:
	if er:
		addon_log('bypassing')
		myheaders = {"User-Agent" : ua,
				 "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				 "Accept-Language" : "en-US,en;q=0.5",
				 #"Accept-Encoding" : "gzip, deflate",
				 "Referer" : "http://iptv.iranproud.com/series/",
				 "Connection" : "close"}
		skiprecords = 0
		for x in range(0, count):
			values = {'displayoption' : 'Recently Added',
					  'limitrecords' : '50',
					  'skiprecords' : str(skiprecords) }
			skiprecords = skiprecords + 50
			data = urllib.urlencode(values)
			if 'Drama' in gener:
				request = urllib2.Request("http://persiairptv.strangled.net/series/category/DRAMA",data, myheaders)
			elif 'Comedy' in gener:
				request = urllib2.Request("http://persiairptv.strangled.net/series/category/COMEDY",data, myheaders)
			elif 'Action' in gener:
				request = urllib2.Request("http://persiairptv.strangled.net/series/category/ACTION",data, myheaders)
			elif 'Cartoon' in gener:
				request = urllib2.Request("http://persiairptv.strangled.net/series/category//CARTOON",data, myheaders)
			else:
				return
			try:
				contents = urllib2.urlopen(request , timeout=20).read()
			except socket_error as e:
				if e.errno != errno.ECONNREFUSED:
					addon_log('socket_error happened ECONNREFUSED')
					xbmc.executebuiltin("XBMC.Notification(Socket Error: ECONNREFUSED ,Check your connection and try again.)")
					return
				else:
					addon_log('socket_error happened UNKNOWN')
					xbmc.executebuiltin("XBMC.Notification(Socket Error: UNKNOWN ,Check your connection and try again.)")
					return
			except urllib2.HTTPError as e:
				addon_log('HTTPError : %s. We failed connecting to IranProud.' %e.code)
				xbmc.executebuiltin("XBMC.Notification(Error: HTTPError ,Please try again.)")
				return
			except socket.timeout, e:
				addon_log('socket.timeout %s ' %e)
				xbmc.executebuiltin("XBMC.Notification(Error: socket.timeout ,Check your connection and try again.)")
				return
			except urllib2.URLError, e:
				if hasattr(e,'reason') and isinstance(e.reason, socket.timeout):
					addon_log('urllib2.URLError Timeout %s ' %e.reason)
					xbmc.executebuiltin("XBMC.Notification(Error: Timeout ,Check your connection and try again.)")
					return
				elif hasattr(e, 'code'):
					addon_log('urllib2.URLError %s ' %e.code)
					xbmc.executebuiltin("XBMC.Notification(Error: URLError. Please try again, %s)" %e.code)
					return
				else:
					# reraise the original error
					raise
			#addon_log(contents)
			soup = BeautifulSoup(contents)
			favstatus = soup.findAll("li", {"class":"favstatus"})
			try:
				for tag in favstatus:
					for line in str(tag).splitlines():
						if 'target' in line:
							ShowPage = re.search(r'href="[^"]+"', line)
							if ShowPage :
								ShowPage = ShowPage.group(0)[6:-1].replace('http://iptv.iranproud.com:80','http://persiairptv.strangled.net')
								if '&amp;' in ShowPage: ShowPage = ShowPage.replace('&amp;', '&')
							ShowNamez = re.search(r'80[/]series[/].+" ', line)
							if ShowNamez:
								ShowNamez = ShowNamez.group(0)[10:-2].replace('-',' ')
								if '&amp;' in ShowNamez: ShowNamez = ShowNamez.replace('&amp;', '&')
						elif 'smallthumb' in line:
							ShowImage = re.search(r'src="[^"]+"', line)
							if ShowImage:
								ShowImage = ShowImage.group(0)[5:-1]
					#addon_log(ShowNamez)
					#addon_log(ShowPage)
					#addon_log(ShowImage)
					addDir(ShowNamez,ShowPage,985,ShowImage,fanart,'','','','','source')
			except:
				addon_log('Problem with extracting shows list.')
				xbmc.executebuiltin("XBMC.Notification(An error occurred.,Please try again.)")
				#raise
				return
	xbmcplugin.endOfDirectory(int(sys.argv[1]))
	
def IranProudSeriesEpisodes(url):
	#mode:985
	import random
	UAList = ["Mozilla/5.0 (iPhone; CPU iPhone OS 9_2 like Mac OS X) AppleWebKit/601.1 (KHTML, like Gecko) CriOS/47.0.2526.70 Mobile/13C71 Safari/601.1.46","Mozilla/5.0 (Linux; U; Android 4.4.4; Nexus 5 Build/KTU84P) AppleWebkit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30","Mozilla/5.0 (Linux; U; Tizen 2.0; en-us) AppleWebKit/537.1 (KHTML, like Gecko) Mobile TizenBrowser/2.0","Mozilla/5.0 (Android 4.4; Mobile; rv:18.0) Gecko/18.0 Firefox/18.0"]
	ua = random.choice(UAList)
	headers = {
	"Connection" : "close",
	"User-Agent" : ua}
	request = urllib2.Request(url, headers=headers)
	x = True
	xc = 0
	addon_log(url)
	while x == True and xc < 5 :
		xc = xc + 1
		addon_log('	Retry loop attempt : %s' %xc)
		try:
			contents = urllib2.urlopen(request, timeout = 10).read()
			x = False
		except socket_error as e:
			if e.errno != errno.ECONNREFUSED:
				addon_log('socket_error happened ECONNREFUSED')
			else:
				addon_log('socket_error happened UNKNOWN')

		except urllib2.HTTPError as e:
			addon_log('HTTPError : %s. We failed connecting to IranProud.' %e.code)
		except socket.timeout, e:
			addon_log('socket.timeout %s ' %e)
		except urllib2.URLError, e:
			if hasattr(e,'reason') and isinstance(e.reason, socket.timeout):
				addon_log('urllib2.URLError Timeout %s ' %e.reason)
			elif hasattr(e, 'code'):
				addon_log('urllib2.URLError %s ' %e.code)
	if x == True:
		addon_log('We failed connect to IranProud. try again later')
		xbmc.executebuiltin("XBMC.Notification(We failed connect to IranProud., try again later)")
		return
	if 'http://mobile.iranproud.net:8080' in url:
		SeasonNumber = re.search(r'"displayseason">.+<[/]a>', contents)
		if SeasonNumber:
			SeasonNumber = SeasonNumber.group(0)[16:-4]
			addDir('[COLOR deepskyblue]Season %s : [/COLOR]' % SeasonNumber,'',0,artpath+'seasons.png',fanart,'','','','','source')
		match = re.findall(r'(?:divBorder4).+(href="[^"]+").+(src="[^"]+")', contents)
		if match:
			for Episodes in match:
				EpisodePage = 'http://mobile.iranproud.net:8080' + Episodes[0][6:-1]
				EpisodeImage = Episodes[1][5:-1]
				EpisodeImage = EpisodeImage.replace('_thumb.jpg', '_bigthumb.jpg')
				EpisodeName = re.search(r'(?:thumbs[/]).+(?:_bigthumb[.]jpg)', EpisodeImage)
				EpisodeName = EpisodeName.group(0)[7:-13].replace('_', ' ')
				addDir(EpisodeName,EpisodePage,986,EpisodeImage,fanart,'','','','','source')
		else:
			addon_log('Problem with extracting episodes list.')
			xbmc.executebuiltin("XBMC.Notification(An error occurred.,Please try again.)")
	elif 'persiairptv.strangled.net' in url:
		SeasonNumber = re.search(r'"displayseason">.+<[/]a>', contents)
		if SeasonNumber:
			SeasonNumber = SeasonNumber.group(0)[16:-4]
			addDir('[COLOR deepskyblue]Season %s : [/COLOR]' % SeasonNumber,'',0,artpath+'seasons.png',fanart,'','','','','source')
		soup = BeautifulSoup(contents)
		favstatus = soup.findAll("li")
		try:
			for tag in favstatus:
				for line in str(tag).splitlines():
					if 'videourl=' in line:
						videourl= re.search(r'videourl=.+"',line)
						if videourl:
							videourl= videourl.group(0)[9:-1].replace('media.iranproud.com','persiairanp3.strangled.net')
							videoname= re.search(r'episodes[/].+',videourl)
							if videoname:
								videoname= videoname.group(0)[9:-4].replace('_',' ')
					if 'img src=' in line:
						videoimage = re.search(r'src="[^"]+"',line)
						videoimage = videoimage.group(0)[5:-1]
				#addon_log(videoname)
				#addon_log(videourl)
				#addon_log(videoimage)
				addLink(videourl, videoname,videoimage,fanart,'','','','',None,'',1)
		except:
			addon_log('Problem with extracting shows list.')
			xbmc.executebuiltin("XBMC.Notification(An error occurred.,Please try again.)")
			raise
			return
	xbmcplugin.endOfDirectory(int(sys.argv[1]))

def IranProudSeriesGetEpisode(url):
	#mode:986
	import random
	UAList = ["Mozilla/5.0 (iPhone; CPU iPhone OS 9_2 like Mac OS X) AppleWebKit/601.1 (KHTML, like Gecko) CriOS/47.0.2526.70 Mobile/13C71 Safari/601.1.46","Mozilla/5.0 (Linux; U; Android 4.4.4; Nexus 5 Build/KTU84P) AppleWebkit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30","Mozilla/5.0 (Linux; U; Tizen 2.0; en-us) AppleWebKit/537.1 (KHTML, like Gecko) Mobile TizenBrowser/2.0","Mozilla/5.0 (Android 4.4; Mobile; rv:18.0) Gecko/18.0 Firefox/18.0"]
	ua = random.choice(UAList)
	headers = {
	"Connection" : "close",  # another way to cover tracks
	"User-Agent" : ua}
	request = urllib2.Request(url, headers=headers)
	try:
		contents = urllib2.urlopen(request,timeout = 10).read()
	except socket_error as e:
		if e.errno != errno.ECONNREFUSED:
			addon_log('socket_error happened ECONNREFUSED')
			xbmc.executebuiltin("XBMC.Notification(Socket Error: ECONNREFUSED ,Check your connection and try again.)")
			return
		else:
			addon_log('socket_error happened UNKNOWN')
			xbmc.executebuiltin("XBMC.Notification(Socket Error: UNKNOWN ,Check your connection and try again.)")
			return
	except urllib2.HTTPError as e:
		addon_log('HTTPError : %s. We failed connecting to IranProud.' %e.code)
		xbmc.executebuiltin("XBMC.Notification(Error: HTTPError ,Please try again.)")
		return
	except socket.timeout, e:
		addon_log('socket.timeout %s ' %e)
		xbmc.executebuiltin("XBMC.Notification(Error: socket.timeout ,Check your connection and try again.)")
		return
	except urllib2.URLError, e:
		if hasattr(e,'reason') and isinstance(e.reason, socket.timeout):
			addon_log('urllib2.URLError Timeout %s ' %e.reason)
			xbmc.executebuiltin("XBMC.Notification(Error: Timeout ,Check your connection and try again.)")
			return
		elif hasattr(e, 'code'):
			addon_log('urllib2.URLError %s ' %e.code)
			xbmc.executebuiltin("XBMC.Notification(Error: URLError. Please try again, %s)" %e.code)
			return
		else:
			# reraise the original error
			raise
	#addon_log(contents)
	if 'persiairptv.strangled.net' in url:
		EpisodeLink = re.search(r'[?]videourl=.+" class', contents)
	else:
		EpisodeLink = re.search(r'videosrc=".+" class', contents)
	if EpisodeLink:
		UAListDesktop = ["Mozilla/5.0 (Windows; U; Windows NT 6.1; de; rv:1.9.1.16) Gecko/20101130 AskTbMYC/3.9.1.14019 Firefox/3.5.16","Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.1.16) Gecko/20101130 AskTbPLTV5/3.8.0.12304 Firefox/3.5.16 (.NET CLR 3.5.30729)","Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.9.1.16) Gecko/20101130 Firefox/3.5.16 GTB7.1 (.NET CLR 3.5.30729)","Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.9.1.16) Gecko/20101130 Firefox/3.5.16 GTB7.1","Mozilla/5.0 (X11; U; Linux x86_64; it; rv:1.9.1.15) Gecko/20101027 Fedora/3.5.15-1.fc12 Firefox/3.5.15","Mozilla/5.0 (X11; U; Linux i686; en-GB; rv:1.9.1.15) Gecko/20101027 Fedora/3.5.15-1.fc12 Firefox/3.5.15","Mozilla/5.0 (Windows; U; Windows NT 5.1; hu; rv:1.9.1.11) Gecko/20100701 Firefox/3.5.11","Mozilla/5.0 (iPhone; U; CPU iPhone OS 4_2_1 like Mac OS X; it-it) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8C148a Safari/6533.18.5","Mozilla/5.0 (iPhone; U; CPU iPhone OS 4_2_1 like Mac OS X; fr) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8C148a Safari/6533.18.5","Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.1.10) Gecko/20100504 Firefox/3.5.11 (.NET CLR 3.5.30729)","Mozilla/5.0 (X11; U; Linux x86_64; de; rv:1.9.1.10) Gecko/20100506 SUSE/3.5.10-0.1.1 Firefox/3.5.10","Mozilla/5.0 (Windows; U; Windows NT 6.0; en-GB; rv:1.9.1.10) Gecko/20100504 Firefox/3.5.10 GTB7.0 ( .NET CLR 3.5.30729)","Mozilla/5.0 (X11; U; Linux x86_64; rv:1.9.1.1) Gecko/20090716 Linux Firefox/3.5.1","Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.3) Gecko/20100524 Firefox/3.5.1","Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090716 Linux Mint/7 (Gloria) Firefox/3.5.1","Mozilla/5.0 (X11; U; Linux i686; en-US) AppleWebKit/534.7 (KHTML, like Gecko) Chrome/7.0.517.24 Safari/534.7","Mozilla/5.0 (X11; U; Linux x86_64; fr-FR) AppleWebKit/534.7 (KHTML, like Gecko) Chrome/7.0.514.0 Safari/534.7","Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.7 (KHTML, like Gecko) Chrome/7.0.514.0 Safari/534.7","Mozilla/5.0 (Windows; U; Windows NT 6.0; ja-JP) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27","Mozilla/5.0 (Macintosh; U; PPC Mac OS X 10_5_8; ja-jp) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27","Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_6; sv-se) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27"]
		EpisodeFinalLink = EpisodeLink.group(0)[10:-7].replace('media.iranproud.com','persiairanp3.strangled.net')
		addon_log('playing link : %s ' % EpisodeFinalLink)
		playmedia(EpisodeFinalLink+'|User-Agent='+random.choice(UAListDesktop)+'&Accept-Language=en-US,en;q=0.5&Accept-Encoding=gzip, deflate&Origin=http://www.iranproud.net&Referer=http://www.iranproud.net/js/jwplayer7/jwplayer.flash.swf')
	else:
		addon_log('Playable link not found')
		xbmc.executebuiltin("XBMC.Notification(An error occurred.,Playable link not found.Please try again.)")

class RedirectHandler(urllib2.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        result = urllib2.HTTPError(req.get_full_url(), code, msg, headers, fp)
        result.status = code
        return result
    http_error_301 = http_error_303 = http_error_307 = http_error_302

def IranProudMoviesCat(cat):
	import random
	import gzip,StringIO
	UAList = ["Mozilla/5.0 (Windows; U; Windows NT 6.1; de; rv:1.9.1.16) Gecko/20101130 AskTbMYC/3.9.1.14019 Firefox/3.5.16","Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.1.16) Gecko/20101130 AskTbPLTV5/3.8.0.12304 Firefox/3.5.16 (.NET CLR 3.5.30729)","Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.9.1.16) Gecko/20101130 Firefox/3.5.16 GTB7.1 (.NET CLR 3.5.30729)","Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.9.1.16) Gecko/20101130 Firefox/3.5.16 GTB7.1","Mozilla/5.0 (X11; U; Linux x86_64; it; rv:1.9.1.15) Gecko/20101027 Fedora/3.5.15-1.fc12 Firefox/3.5.15","Mozilla/5.0 (X11; U; Linux i686; en-GB; rv:1.9.1.15) Gecko/20101027 Fedora/3.5.15-1.fc12 Firefox/3.5.15","Mozilla/5.0 (Windows; U; Windows NT 5.1; hu; rv:1.9.1.11) Gecko/20100701 Firefox/3.5.11","Mozilla/5.0 (iPhone; U; CPU iPhone OS 4_2_1 like Mac OS X; it-it) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8C148a Safari/6533.18.5","Mozilla/5.0 (iPhone; U; CPU iPhone OS 4_2_1 like Mac OS X; fr) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8C148a Safari/6533.18.5","Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.1.10) Gecko/20100504 Firefox/3.5.11 (.NET CLR 3.5.30729)","Mozilla/5.0 (X11; U; Linux x86_64; de; rv:1.9.1.10) Gecko/20100506 SUSE/3.5.10-0.1.1 Firefox/3.5.10","Mozilla/5.0 (Windows; U; Windows NT 6.0; en-GB; rv:1.9.1.10) Gecko/20100504 Firefox/3.5.10 GTB7.0 ( .NET CLR 3.5.30729)","Mozilla/5.0 (X11; U; Linux x86_64; rv:1.9.1.1) Gecko/20090716 Linux Firefox/3.5.1","Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.3) Gecko/20100524 Firefox/3.5.1","Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090716 Linux Mint/7 (Gloria) Firefox/3.5.1","Mozilla/5.0 (X11; U; Linux i686; en-US) AppleWebKit/534.7 (KHTML, like Gecko) Chrome/7.0.517.24 Safari/534.7","Mozilla/5.0 (X11; U; Linux x86_64; fr-FR) AppleWebKit/534.7 (KHTML, like Gecko) Chrome/7.0.514.0 Safari/534.7","Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.7 (KHTML, like Gecko) Chrome/7.0.514.0 Safari/534.7","Mozilla/5.0 (Windows; U; Windows NT 6.0; ja-JP) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27","Mozilla/5.0 (Macintosh; U; PPC Mac OS X 10_5_8; ja-jp) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27","Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_6; sv-se) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27"]
	ua = random.choice(UAList)
	myheaders = {"User-Agent" : ua,
	"Connection" : "close",
	"Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"Accept-Language" : "en-US,en;q=0.5",
	"Accept-Encoding" : "gzip, deflate",
	"Referer" : "http://iptv.iranproud.com/movies/",
	"cache-control" : "no-cache"}
	addon_log('##### Getting totalrows value')
	addon_log('Opening directly')
	er = 0
	x = True
	xc = 0
	while x == True and xc < 4 :
		xc = xc + 1
		addon_log('	Retry loop attempt : %s' %xc)
		try:
			if 'Comedy' in cat:
				directurl = 'http://iptv.iranproud.com/movies/COMEDY'
			elif 'Drama' in cat:
				directurl = 'http://iptv.iranproud.com/movies/DRAMA'
			elif 'Action' in cat:
				directurl = 'http://iptv.iranproud.com/movies/ACTION'
			elif 'Classic' in cat:
				directurl = 'http://iptv.iranproud.com/movies/CLASSIC'
			elif 'TV & Cinema' in cat:
				directurl = 'http://iptv.iranproud.com/movies/TV+%26+CINEMA'
			else:
				return
			request = urllib2.Request(directurl, headers=myheaders)
			contents = urllib2.urlopen(request, timeout = 9)
			gzip_filehandle=gzip.GzipFile(fileobj=StringIO.StringIO(contents.read()))
			html = gzip_filehandle.read()
			contents.close()
			x = False
			break
		except socket_error as e:
			if e.errno != errno.ECONNREFUSED:
				addon_log('		socket_error happened ECONNREFUSED, retrying after 2 second delay')
				time.sleep(1)
			else:
				addon_log('		socket_error happened UNKNOWN, retrying after 2 second delay')
				er = 403
				x = False
		except urllib2.HTTPError as e:
			er = e.code
			x = False
			addon_log('		HTTPError : %s. We failed connecting to IranProud directly.' %e.code)
			if e.code == 403:addon_log('		Error 403 Forbidden. Website is blocked,you live in Iran?! Let me bypass it for you!')
		except socket.timeout, e:
			addon_log('		socket.timeout %s ' %e)
		except urllib2.URLError, e:
			if hasattr(e,'reason') and isinstance(e.reason, socket.timeout):
				addon_log('		urllib2.URLError Timeout %s ' %e.reason)
			elif hasattr(e, 'code'):
				addon_log('		urllib2.URLError %s ' %e.code)
			else:
				if hasattr(e,'reason'):addon_log('		urllib2.URLError %s ' %e.reason)
	if x == True:
		addon_log('		We failed directly connect to IranProud. let me try other methods it might help!')
		er=403
	addon_log('		** er : %s' %er)
	if er < 400:
		soup = BeautifulSoup(html)
		tr = soup.find("div", {"id":"gridWrapper"})
		try:
			for tag in tr:
				for line in str(tag).splitlines():
					if 'displayoption' in line:
						totalrows = re.search(r'totalrows=".+"><',line)
						if totalrows:
							totalrows = totalrows.group(0)[11:-3]
							addon_log('		+totalrows found : %s' %totalrows)
							totalrows = int(totalrows)
						break
		except:
			addon_log('		An error occurred finding totalrows')
			xbmc.executebuiltin("XBMC.Notification(An error occurred finding totalrows)")
			return
	if er > 400:
		addon_log('Opening using fake domain')
		x = True
		xc = 0
		er = 0
		while x == True and xc < 5 :
			xc = xc + 1
			addon_log('	Retry loop attempt : %s' %xc)
			try:
				if 'Comedy' in cat:
					directurl = 'http://persiairptv.strangled.net/movies/COMEDY'
				elif 'Drama' in cat:
					directurl = 'http://persiairptv.strangled.net/movies/DRAMA'
				elif 'Action' in cat:
					directurl = 'http://persiairptv.strangled.net/movies/ACTION'
				elif 'Classic' in cat:
					directurl = 'http://persiairptv.strangled.net/movies/CLASSIC'
				elif 'TV & Cinema' in cat:
					directurl = 'http://persiairptv.strangled.net/movies/TV+%26+CINEMA'
				else:
					return
				request = urllib2.Request(directurl, headers=myheaders)
				contents = urllib2.urlopen(request)
				gzip_filehandle=gzip.GzipFile(fileobj=StringIO.StringIO(contents.read()))
				html = gzip_filehandle.read()
				contents.close()
				soup = BeautifulSoup(html)
				tr = soup.find("div", {"id":"gridWrapper"})
				try:
					for tag in tr:
						for line in str(tag).splitlines():
							if 'displayoption' in line:
								totalrows = re.search(r'totalrows=".+"><',line)
								if totalrows:
									totalrows = totalrows.group(0)[11:-3]
									addon_log('		+totalrows found : %s' %totalrows)
									totalrows = int(totalrows)
								break
				except:
					addon_log('		An error occurred finding totalrows')
					xbmc.executebuiltin("XBMC.Notification(An error occurred finding totalrows)")
					return
				x = False
			except socket_error as e:
				if e.errno != errno.ECONNREFUSED:
					addon_log('		socket_error happened ECONNREFUSED, retrying after 2 second delay')
					time.sleep(2)
				else:
					addon_log('		socket_error happened UNKNOWN, retrying after 2 second delay')
					er = 403403
					x = False
			except urllib2.HTTPError as e:
				er = e.code
				x = False
				addon_log('HTTPError : %s. We failed connecting to IranProud with fake domain.' %e.code)
				if er == 403:
					er=403403
					addon_log('		Error 403 Forbidden. Fake domain is blocked!!! Let try another way!')
			except socket.timeout, e:
				addon_log('		socket.timeout %s ' %e)
			except urllib2.URLError, e:
				if hasattr(e,'reason') and isinstance(e.reason, socket.timeout):
					addon_log('		urllib2.URLError Timeout %s ' %e.reason)
				elif hasattr(e, 'code'):
					addon_log('		urllib2.URLError %s ' %e.code)
				else:
					if hasattr(e,'reason'):addon_log('		urllib2.URLError %s ' %e.reason)
		if x == True:
			addon_log('		We failed connecting to IranProud using fake domain address.')
			er=403403 #To check again using glype proxy maybe it work !
	if er == 403403:#If website is blocked by ISP open it with my customized Glype proxy
		addon_log('Opening using Glype Proxy')
		ua = random.choice(UAList)
		myheaders = {"User-Agent" : ua,
					"Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
					"Accept-Language" : "en-US,en;q=0.5",
					"Accept-Encoding" : "gzip, deflate",
					"Connection" : "keep-alive"}
		xc = 0 
		x = True
		while x == True and xc < 5 :
			xc = xc + 1
			addon_log('	Retry loop attempt : %s' %xc)
			try:
				if 'Comedy' in cat:
					values = {'u' : 'http://iptv.iranproud.com/movies/COMEDY',
						'encodeURL' : 'on'}
					data = urllib.urlencode(values)
				elif 'Drama' in cat:
					values = {'u' : 'http://iptv.iranproud.com/movies/DRAMA',
						'encodeURL' : 'on'}
					data = urllib.urlencode(values)
				elif 'Action' in cat:
					values = {'u' : 'http://iptv.iranproud.com/movies/ACTION',
						'encodeURL' : 'on'}
					data = urllib.urlencode(values)
				elif 'Classic' in cat:
					values = {'u' : 'http://iptv.iranproud.com/movies/CLASSIC/',
						'encodeURL' : 'on'}
					data = urllib.urlencode(values)
				elif 'TV & Cinema' in cat:
					values = {'u' : 'http://iptv.iranproud.com/movies/TV+%26+CINEMA',
						'encodeURL' : 'on'}
					data = urllib.urlencode(values)
				else:
					return
				#make our request to send URL using post to Glype
				request = urllib2.Request('http://persia.strangled.net/.kodi/includes/process.php?action=update',data, headers=myheaders)
				opener = urllib2.build_opener(RedirectHandler())#avoid autoredirection so we could get Location header
				contents = opener.open(request)#sending Post request
				global Cookie
				Cookie = contents.info().getheader('Set-Cookie')#Glype Cookie
				RedirectPage = contents.info().getheader('Location')#Glype hotlink for our URL
				addon_log('		Glype hotlink for our URL : %s' %RedirectPage)
				addon_log('		Glype Cookie : %s' %Cookie)
				#using cookie to open Glype hotlink for our URL
				myheaders = {"User-Agent" : ua,
					"Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
					"Accept-Language" : "en-US,en;q=0.5",
					"Accept-Encoding" : "gzip, deflate",
					"Cookie" : Cookie,
					"Connection" : "keep-alive"}
				request = urllib2.Request(RedirectPage, headers=myheaders)
				contents = urllib2.urlopen(request)
				gzip_filehandle=gzip.GzipFile(fileobj=StringIO.StringIO(contents.read()))
				html = gzip_filehandle.read()
				contents.close()
				soup = BeautifulSoup(html)
				tr = soup.find("div", {"id":"gridWrapper"})
				try:
					for tag in tr:
						for line in str(tag).splitlines():
							if 'displayoption' in line:
								totalrows = re.search(r'totalrows=".+"><',line)
								if totalrows:
									totalrows = totalrows.group(0)[11:-3]
									addon_log('		+totalrows found : %s' %totalrows)
									totalrows = int(totalrows)
								break
				except:
					addon_log('		An error occurred finding totalrows using proxy')
					xbmc.executebuiltin("XBMC.Notification(An error occurred finding totalrows)")
					return
				x = False
				break
			except socket_error as e:
				if e.errno != errno.ECONNREFUSED:
					addon_log('		socket_error happened ECONNREFUSED, retrying after 2 second delay')
					time.sleep(2)
				else:
					addon_log('		socket_error happened UNKNOWN, retrying after 2 second delay')
			except urllib2.HTTPError as e:
				x = False
				addon_log('		HTTPError : %s We failed connecting to IranProud,Please try again later' %e.code())
				xbmc.executebuiltin("XBMC.Notification(HTTPError : %s We failed connecting to IranProud,Please try again later)" %e.code())
				return
			except socket.timeout, e:
				addon_log('		socket.timeout %s ' %e)
			except urllib2.URLError, e:
				if hasattr(e,'reason') and isinstance(e.reason, socket.timeout):
					addon_log('		urllib2.URLError Timeout %s ' %e.reason)
				elif hasattr(e, 'code'):
					addon_log('		urllib2.URLError %s ' %e.code)
				else:
					if hasattr(e,'reason'):addon_log('		urllib2.URLError %s ' %e.reason)
		if x == True:
			addon_log('		I tried all my best but none of the 3 method worked! :(.')
			xbmc.executebuiltin("XBMC.Notification(I tried all my best but,none of the 3 method worked!)")
			return
	addon_log('##### Sending Post request and extracting Movies list')
#--------Start-------- Calculating how many time to send Post request and extracting Movies info
	if 'Action' in cat: #nasty fix !!
		ci = (totalrows / 25)
	elif 'Drama' in cat:
		ci = (totalrows / 25)
	else:
		ci = (totalrows / 25)+1
	addon_log('Based on totalrows we need to loop : %s time to get all movies' %ci) #to get all movies
	i = 0 #increasing step in loop for Skiprecords value(+25)
	for num in range(0,ci):
		values = {'displayoption' : 'Recently Added',
				'limitrecords' : '25',
				'skiprecords' : str(i)}
		data = urllib.urlencode(values)
		x = True
		xc = 0
		addon_log('	** loop : %s' %(num+1))
		addon_log('	** skiprecords : %s' %i)
		while x == True and xc < 5 :
			xc = xc + 1
			addon_log('	Retry loop attempt : %s' %xc)
			try:
				if er == 403403:request = urllib2.Request(RedirectPage,data, headers=myheaders)
				if er < 400 or er == 403:request = urllib2.Request(directurl,data, headers=myheaders)
				contents = urllib2.urlopen(request,timeout=10)
				gzip_filehandle=gzip.GzipFile(fileobj=StringIO.StringIO(contents.read()))
				html = gzip_filehandle.read()
				contents.close()
				if er == 403403:IranProudMoviesList(html,True)
				if er < 400 or er == 403:IranProudMoviesList(html,False)
				i = i + 25
				x = False
				break
			except socket_error as e:
				if e.errno != errno.ECONNREFUSED:
					addon_log('		socket_error happened ECONNREFUSED, retrying after 2 second delay')
					time.sleep(2)
				else:
					addon_log('		socket_error happened UNKNOWN, retrying after 2 second delay')
			except urllib2.HTTPError as e:
				x = False
				addon_log('		HTTPError : %s We failed connecting to IranProud,Please try again later' %e.code())
				xbmc.executebuiltin("XBMC.Notification(HTTPError : %s We failed connecting to IranProud,Please try again later)" %e.code())
				break
			except socket.timeout, e:
				addon_log('		socket.timeout %s ' %e)
			except urllib2.URLError, e:
				if hasattr(e,'reason') and isinstance(e.reason, socket.timeout):
					addon_log('		urllib2.URLError Timeout %s ' %e.reason)
				elif hasattr(e, 'code'):
					addon_log('		urllib2.URLError %s ' %e.code)
				else:
					# reraise the original error
					raise
		if x == True:
			if (num+1)>=ci:
				pass
			else:
				if i >= totalrows :
					pass
				else:
					addon_log('We have problem accessing IranProud server,try again later')
					xbmc.executebuiltin("XBMC.Notification(We have problem accessing IranProud server,try again later)")
#--------End-------- Calculating how many time to send Post request and extracting Movies info
	xbmcplugin.endOfDirectory(int(sys.argv[1]))

def IranProudMoviesList(contents,proxy):
	addon_log('		IranProudMoviesList function')
	soup = BeautifulSoup(contents)
	favstatus = soup.findAll("li", {"class":"favstatus"})
	MovieName = ''
	for tag in favstatus:
		for line in str(tag).splitlines():
			if proxy == False:
				if 'divMovHold' in line:
					MoviePage = re.search(r'href=".+target=',line)
					if MoviePage:
						MoviePage = 'http://iptv.iranproud.com'+MoviePage.group(0)[6:-9]
						MoviePage = urllib.unquote(MoviePage).decode('utf8')
				elif 'divMovPic' in line:
					MoviePic = re.search(r'http.+.jpg',line)
					if MoviePic:
						MoviePic = MoviePic.group(0)
						MoviePic = urllib.unquote(MoviePic).decode('utf8')
						MovieName = re.search(r'thumbs[/].+_thumb',MoviePic)
						if MovieName:
							MovieName = MovieName.group(0)[7:-6]
							MovieName = MovieName.replace('_',' ')
							if MovieName[-2:] == '01':MovieName=MovieName[:-2]
							if MovieName[-1:] == '1':MovieName=MovieName[:-1]
							if MovieName[:5] == 'film ':MovieName=MovieName[5:]
			elif proxy == True:
				if 'divMovHold' in line:
					b64 = re.search(r'browse[.]php[?]u=.+&amp',line)
					b64 = b64.group(0)[13:-4]
					b64 = urllib.unquote(b64).decode('utf8')
					line = 'http'+base64.b64decode(b64)
					MoviePage = line
				elif 'divMovPic' in line:
					b64 = re.search(r'browse[.]php[?]u=.+&amp',line)
					b64 = b64.group(0)[13:-4]
					b64 = urllib.unquote(b64).decode('utf8')
					line = 'http'+base64.b64decode(b64)
					MoviePic = line
					MovieName = re.search(r'thumbs[/].+_thumb',MoviePic)
					if MovieName:
						MovieName = MovieName.group(0)[7:-6]
						MovieName = MovieName.replace('_',' ')
						if MovieName[-2:] == '01':MovieName=MovieName[:-2]
						if MovieName[-1:] == '1':MovieName=MovieName[:-1]
						if MovieName[:5] == 'film ':MovieName=MovieName[5:]
			if MovieName != '' :
				#addon_log('MovieName : %s' %MovieName)
				#addon_log('MoviePage : %s' %MoviePage)
				#addon_log('MoviePic : %s' %MoviePic)
				addDir(MovieName,MoviePage,9990,MoviePic,fanart,'','','','','source')
				MovieName = ''
				
def IranProudPlayMovie(url):
	import random
	import gzip,StringIO
	addon_log('IranProudPlayMovie function')
	if '&amp;' in url:url=url.replace('&amp;','&')
	UAList = ["Mozilla/5.0 (Windows; U; Windows NT 6.1; de; rv:1.9.1.16) Gecko/20101130 AskTbMYC/3.9.1.14019 Firefox/3.5.16","Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.1.16) Gecko/20101130 AskTbPLTV5/3.8.0.12304 Firefox/3.5.16 (.NET CLR 3.5.30729)","Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.9.1.16) Gecko/20101130 Firefox/3.5.16 GTB7.1 (.NET CLR 3.5.30729)","Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.9.1.16) Gecko/20101130 Firefox/3.5.16 GTB7.1","Mozilla/5.0 (X11; U; Linux x86_64; it; rv:1.9.1.15) Gecko/20101027 Fedora/3.5.15-1.fc12 Firefox/3.5.15","Mozilla/5.0 (X11; U; Linux i686; en-GB; rv:1.9.1.15) Gecko/20101027 Fedora/3.5.15-1.fc12 Firefox/3.5.15","Mozilla/5.0 (Windows; U; Windows NT 5.1; hu; rv:1.9.1.11) Gecko/20100701 Firefox/3.5.11","Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.1.10) Gecko/20100504 Firefox/3.5.11 (.NET CLR 3.5.30729)","Mozilla/5.0 (X11; U; Linux x86_64; de; rv:1.9.1.10) Gecko/20100506 SUSE/3.5.10-0.1.1 Firefox/3.5.10","Mozilla/5.0 (Windows; U; Windows NT 6.0; en-GB; rv:1.9.1.10) Gecko/20100504 Firefox/3.5.10 GTB7.0 ( .NET CLR 3.5.30729)","Mozilla/5.0 (X11; U; Linux x86_64; rv:1.9.1.1) Gecko/20090716 Linux Firefox/3.5.1","Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.3) Gecko/20100524 Firefox/3.5.1","Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090716 Linux Mint/7 (Gloria) Firefox/3.5.1","Mozilla/5.0 (X11; U; Linux i686; en-US) AppleWebKit/534.7 (KHTML, like Gecko) Chrome/7.0.517.24 Safari/534.7","Mozilla/5.0 (X11; U; Linux x86_64; fr-FR) AppleWebKit/534.7 (KHTML, like Gecko) Chrome/7.0.514.0 Safari/534.7","Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.7 (KHTML, like Gecko) Chrome/7.0.514.0 Safari/534.7","Mozilla/5.0 (Windows; U; Windows NT 6.0; ja-JP) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27","Mozilla/5.0 (Macintosh; U; PPC Mac OS X 10_5_8; ja-jp) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27","Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_6; sv-se) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27"]
	ua = random.choice(UAList)
	myheaders = {"User-Agent" : ua,
		"Connection" : "close",
		"Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language" : "en-US,en;q=0.5",
		"Accept-Encoding" : "gzip, deflate",
		"Referer" : "http://iptv.iranproud.com/movies/",
		"cache-control" : "no-cache"}
	addon_log('##### Opening directly to get video url')
	x = True
	xc = 0
	er = 0
	while x == True and xc < 4 :
		xc = xc + 1
		addon_log('	Retry loop attempt : %s' %xc)
		try:
			request = urllib2.Request(url, headers=myheaders)
			contents = urllib2.urlopen(request, timeout = 10)
			gzip_filehandle=gzip.GzipFile(fileobj=StringIO.StringIO(contents.read()))
			html = gzip_filehandle.read()
			contents.close()
			x = False
			break
		except socket_error as e:
			if e.errno != errno.ECONNREFUSED:
				addon_log('		socket_error happened ECONNREFUSED, retrying after 2 second delay')
				time.sleep(2)
			else:
				addon_log('		socket_error happened UNKNOWN, retrying after 2 second delay')
				er = 403
				x = False
		except urllib2.HTTPError as e:
			er = e.code
			x = False
			addon_log('		HTTPError : %s. We failed connecting to IranProud directly.' %e.code)
			if e.code == 403 : addon_log('		Error 403 Forbidden. Website is blocked,you live in Iran?! Let me bypass it for you!')
		except socket.timeout, e:
			addon_log('		socket.timeout %s ' %e)
		except urllib2.URLError, e:
			if hasattr(e,'reason') and isinstance(e.reason, socket.timeout):
				addon_log('		urllib2.URLError Timeout %s ' %e.reason)
			elif hasattr(e, 'code'):
				addon_log('		urllib2.URLError %s ' %e.code)
			else:
				if hasattr(e,'reason'):addon_log('		urllib2.URLError %s ' %e.reason)
	if x == True:
		addon_log('		We failed directly connect to IranProud. let me try other methods it might help!')
		er = 403
	if er < 400:
		try:
			soup = BeautifulSoup(html)
			divLP04 = soup.findAll("div", {"id":"divLP04"})
			videourl= re.search(r'videourl=.+class',str(divLP04))
			videourl= videourl.group(0)[9:-7]
			addon_log('		Video URL : %s' %videourl)
			playmedia(videourl+'|User-Agent='+ua+'&Accept-Language=en-US,en;q=0.5&Accept-Encoding=gzip, deflate&Origin=http://www.iranproud.net&Referer=http://www.iranproud.net/js/jwplayer7/jwplayer.flash.swf')
		except:
			xbmc.executebuiltin("XBMC.Notification(An error occurred.,Video URL not found.)")
			addon_log('		An error occurred.,Video URL not found')
	if er > 403:
		addon_log('##### Opening using fake domain to get video url')
		x = True
		xc = 0
		while x == True and xc < 5 :
			xc = xc + 1
			addon_log('	Retry loop attempt : %s' %xc)
			try:
				request = urllib2.Request(url.replace('iptv.iranproud.com','persiairptv.strangled.net'), headers=myheaders)
				contents = urllib2.urlopen(request)
				gzip_filehandle=gzip.GzipFile(fileobj=StringIO.StringIO(contents.read()))
				html = gzip_filehandle.read()
				contents.close()
				try:
					soup = BeautifulSoup(html)
					divLP04 = soup.findAll("div", {"id":"divLP04"})
					videourl= re.search(r'videourl=.+class',str(divLP04))
					videourl= videourl.group(0)[9:-7].replace('media.iranproud.com','persiairanp3.strangled.net')
					addon_log('		Video URL : %s' %videourl)
					playmedia(videourl+'|User-Agent='+ua+'&Accept-Language=en-US,en;q=0.5&Accept-Encoding=gzip, deflate&Origin=http://www.iranproud.net&Referer=http://www.iranproud.net/js/jwplayer7/jwplayer.flash.swf')
				except:
					xbmc.executebuiltin("XBMC.Notification(An error occurred.,Video URL not found.)")
					addon_log('		An error occurred.,Video URL not found.')
					return
				x = False
				break
			except socket_error as e:
				if e.errno != errno.ECONNREFUSED:
					addon_log('		socket_error happened ECONNREFUSED, retrying after 2 second delay')
					time.sleep(2)
				else:
					addon_log('		socket_error happened UNKNOWN, retrying after 2 second delay')
			except urllib2.HTTPError as e:
				er = e.code
				x = False
				addon_log('		HTTPError : %s. We failed connecting to IranProud with fake domain.' %e.code)
				if er == 403:
					addon_log('		Error 403 Forbidden. Fake domain is blocked!!! Let try another way!')
					er=403403
			except socket.timeout, e:
				addon_log('		socket.timeout %s ' %e)
			except urllib2.URLError, e:
				if hasattr(e,'reason') and isinstance(e.reason, socket.timeout):
					addon_log('		urllib2.URLError Timeout %s ' %e.reason)
				elif hasattr(e, 'code'):
					addon_log('		urllib2.URLError %s ' %e.code)
				else:
					if hasattr(e,'reason'):addon_log('		urllib2.URLError %s ' %e.reason)
		if x == True:
			addon_log('		We failed connecting to IranProud using fake domain address.')
			er=403403 #to check again using glype proxy maybe it work !
	if er == 403403:
		addon_log('##### Trying another way to bypass 403 error (glype)')
		x = True
		xc = 0
		er = 0
		myheaders = {"User-Agent" : ua,
					"Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
					"Accept-Language" : "en-US,en;q=0.5",
					"Accept-Encoding" : "gzip, deflate",
					"Cookie" : Cookie,
					"Connection" : "keep-alive"}
		url = url.replace('http','')
		url = 'http://persia.strangled.net/.kodi/browse.php?u='+base64.b64encode(url)+'&b=0&f=norefer'
		while x == True and xc < 5 :
			xc = xc + 1
			addon_log('	Retry loop attempt : %s' %xc)
			try:
				request = urllib2.Request(url, headers=myheaders)
				contents = urllib2.urlopen(request)
				gzip_filehandle=gzip.GzipFile(fileobj=StringIO.StringIO(contents.read()))
				html = gzip_filehandle.read()
				contents.close()
				try:
					soup = BeautifulSoup(html)
					divLP04 = soup.findAll("div", {"id":"divLP04"})
					videourl= re.search(r'href=.+class',str(divLP04))
					videourl = urllib.unquote(videourl.group(0)).decode('utf8')
					videourl = videourl[26:-15]
					videourl = base64.b64decode(videourl)
					videourl= re.search(r'videourl=.+',str(videourl))
					videourl= videourl.group(0)[9:].replace('media.iranproud.com','persiairanp3.strangled.net')
					addon_log('Video URL : %s' %videourl)
					playmedia(videourl+'|User-Agent='+ua+'&Accept-Language=en-US,en;q=0.5&Accept-Encoding=gzip, deflate&Origin=http://www.iranproud.net&Referer=http://www.iranproud.net/js/jwplayer7/jwplayer.flash.swf')
				except:
					xbmc.executebuiltin("XBMC.Notification(An error occurred.,Video URL not found.)")
					addon_log('An error occurred. Video URL not found')
				x = False
				break
			except socket_error as e:
				if e.errno != errno.ECONNREFUSED:
					addon_log('		socket_error happened ECONNREFUSED, retrying after 2 second delay')
					time.sleep(2)
				else:
					addon_log('		socket_error happened UNKNOWN, retrying after 2 second delay')
			except urllib2.HTTPError as e:
				er = e.code
				x = False
				addon_log('		HTTPError : %s. We failed connecting to IranProud using proxy.' %e.code)
			except socket.timeout, e:
				addon_log('		socket.timeout %s ' %e)
			except urllib2.URLError, e:
				if hasattr(e,'reason') and isinstance(e.reason, socket.timeout):
					addon_log('		urllib2.URLError Timeout %s ' %e.reason)
				elif hasattr(e, 'code'):
					addon_log('		urllib2.URLError %s ' %e.code)
				else:
					# reraise the original error
					raise
		if x == True:
			addon_log('		I tried all my best but none of the 3 method worked! :(.')
			xbmc.executebuiltin("XBMC.Notification(I tried all my best but,none of the 3 method worked!)")
			return
	else:
		return
	
def IranProudMoviesNewReleases():
	import random
	er = False
	UAList = ["Mozilla/5.0 (iPhone; CPU iPhone OS 9_2 like Mac OS X) AppleWebKit/601.1 (KHTML, like Gecko) CriOS/47.0.2526.70 Mobile/13C71 Safari/601.1.46","Mozilla/5.0 (Linux; U; Android 4.4.4; Nexus 5 Build/KTU84P) AppleWebkit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30","Mozilla/5.0 (Linux; U; Tizen 2.0; en-us) AppleWebKit/537.1 (KHTML, like Gecko) Mobile TizenBrowser/2.0","Mozilla/5.0 (Android 4.4; Mobile; rv:18.0) Gecko/18.0 Firefox/18.0"]
	ua = random.choice(UAList)
	myheaders = {"User-Agent" : ua}
	try:
		request = urllib2.Request('http://mobile.iranproud.net:8080/irani-best-movies', headers=myheaders)
		contents = urllib2.urlopen(request, timeout = 10).read()
	except socket_error as e:
		er = True
		if e.errno != errno.ECONNREFUSED:
			addon_log('socket_error happened ECONNREFUSED')
		else:
			addon_log('socket_error happened UNKNOWN')
	except urllib2.HTTPError as e:
		er = True
		addon_log('HTTPError : %s. We failed connecting to IranProud.' %e.code)
	except socket.timeout, e:
		er = True
		addon_log('socket.timeout %s ' %e)
	except urllib2.URLError, e:
		er = True
		if hasattr(e,'reason') and isinstance(e.reason, socket.timeout):
			addon_log('urllib2.URLError Timeout %s ' %e.reason)
		elif hasattr(e, 'code'):
			addon_log('urllib2.URLError %s ' %e.code)
	if er:
		addon_log('bypassing')
		myheaders = {"User-Agent" : ua,
				 "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				 "Accept-Language" : "en-US,en;q=0.5",
				 #"Accept-Encoding" : "gzip, deflate",
				 "Referer" : "http://iptv.iranproud.com/series/",
				 "Connection" : "close"}
		try:
			request = urllib2.Request('http://persiairptv.strangled.net/movies', headers=myheaders)
			contents = urllib2.urlopen(request).read()
		except socket_error as e:
			er = True
			if e.errno != errno.ECONNREFUSED:
				addon_log('socket_error happened ECONNREFUSED')
				xbmc.executebuiltin("XBMC.Notification(Socket Error: ECONNREFUSED ,Check your connection and try again.)")
				return
			else:
				addon_log('socket_error happened UNKNOWN')
				xbmc.executebuiltin("XBMC.Notification(Socket Error: UNKNOWN ,Check your connection and try again.)")
				return
		except urllib2.HTTPError as e:
			er = True
			addon_log('HTTPError : %s. We failed connecting to IranProud.' %e.code)
			xbmc.executebuiltin("XBMC.Notification(Error: HTTPError ,Please try again.)")
			return
		except socket.timeout, e:
			er = True
			addon_log('socket.timeout %s ' %e)
			xbmc.executebuiltin("XBMC.Notification(Error: socket.timeout ,Check your connection and try again.)")
			return
		except urllib2.URLError, e:
			er = True
			if hasattr(e,'reason') and isinstance(e.reason, socket.timeout):
				addon_log('urllib2.URLError Timeout %s ' %e.reason)
				xbmc.executebuiltin("XBMC.Notification(Error: Timeout ,Check your connection and try again.)")
				return
			elif hasattr(e, 'code'):
				addon_log('urllib2.URLError %s ' %e.code)
				xbmc.executebuiltin("XBMC.Notification(Error: URLError. Please try again, %s)" %e.code)
				return
	if er == False:
		soup = BeautifulSoup(contents)
		MovieSS21 = soup.find("div", {"id":"MovieSS21"})
		moviename = ''
		movielink = ''
		movieimage = ''
		for tag in MovieSS21:
			for line in str(tag).splitlines():
				if 'img src=' in line:
					movieimage = re.search(r'src="[^"]+"',line)
					movieimage = movieimage.group(0)[5:-1]
					#addon_log(movieimage)
				elif 'mask3' in line:
					movielink = re.search(r'href="[^"]+"',line)
					movielink = 'http://mobile.iranproud.net:8080'+movielink.group(0)[6:-1]
					#addon_log(movielink)
				elif 'SSh3' in line:
					moviename = re.search(r'"SSh3">.+<[/]div>',line)
					moviename = moviename.group(0)[7:-6]
					#addon_log(moviename)
			if moviename!='' or movielink!='' or movieimage!='':
				addDir(moviename,movielink,986,movieimage,fanart,'','','','','source')
			moviename=''
			movielink=''
			movieimage=''
	else:
		soup = BeautifulSoup(contents)
		MovieSS21 = soup.find("div", {"id":"MOVSS2"})
		for tag in MovieSS21:
			if 'href' in str(tag):
				movielink = re.search(r'href="[^"]+"',str(tag))
				movielink = 'http://persiairptv.strangled.net'+movielink.group(0)[6:-1]
				movieimage = re.search(r'src="[^"]+"',str(tag))
				movieimage = movieimage.group(0)[5:-1]
				moviename = re.search(r'thumbs[/].+_thumb.',str(tag))
				moviename = moviename.group(0)[7:-7].replace('_',' ')
				addDir(moviename,movielink,986,movieimage,fanart,'','','','','source')
	xbmcplugin.endOfDirectory(int(sys.argv[1]))

def IranProudMoviesMostPopular():
	import random
	er = False
	UAList = ["Mozilla/5.0 (iPhone; CPU iPhone OS 9_2 like Mac OS X) AppleWebKit/601.1 (KHTML, like Gecko) CriOS/47.0.2526.70 Mobile/13C71 Safari/601.1.46","Mozilla/5.0 (Linux; U; Android 4.4.4; Nexus 5 Build/KTU84P) AppleWebkit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30","Mozilla/5.0 (Linux; U; Tizen 2.0; en-us) AppleWebKit/537.1 (KHTML, like Gecko) Mobile TizenBrowser/2.0","Mozilla/5.0 (Android 4.4; Mobile; rv:18.0) Gecko/18.0 Firefox/18.0"]
	ua = random.choice(UAList)
	myheaders = {"User-Agent" : ua}
	try:
		request = urllib2.Request('http://mobile.iranproud.net:8080/irani-best-movies', headers=myheaders)
		contents = urllib2.urlopen(request, timeout = 10).read()
	except socket_error as e:
		er = True
		if e.errno != errno.ECONNREFUSED:
			addon_log('socket_error happened ECONNREFUSED')
		else:
			addon_log('socket_error happened UNKNOWN')
	except urllib2.HTTPError as e:
		er = True
		addon_log('HTTPError : %s. We failed connecting to IranProud.' %e.code)
	except socket.timeout, e:
		er = True
		addon_log('socket.timeout %s ' %e)
	except urllib2.URLError, e:
		er = True
		if hasattr(e,'reason') and isinstance(e.reason, socket.timeout):
			addon_log('urllib2.URLError Timeout %s ' %e.reason)
		elif hasattr(e, 'code'):
			addon_log('urllib2.URLError %s ' %e.code)
	if er:
		addon_log('bypassing')
		myheaders = {"User-Agent" : ua,
				 "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				 "Accept-Language" : "en-US,en;q=0.5",
				 #"Accept-Encoding" : "gzip, deflate",
				 "Referer" : "http://iptv.iranproud.com/series/",
				 "Connection" : "close"}
		try:
			request = urllib2.Request('http://persiairptv.strangled.net/movies', headers=myheaders)
			contents = urllib2.urlopen(request).read()
		except socket_error as e:
			er = True
			if e.errno != errno.ECONNREFUSED:
				addon_log('socket_error happened ECONNREFUSED')
				xbmc.executebuiltin("XBMC.Notification(Socket Error: ECONNREFUSED ,Check your connection and try again.)")
				return
			else:
				addon_log('socket_error happened UNKNOWN')
				xbmc.executebuiltin("XBMC.Notification(Socket Error: UNKNOWN ,Check your connection and try again.)")
				return
		except urllib2.HTTPError as e:
			er = True
			addon_log('HTTPError : %s. We failed connecting to IranProud.' %e.code)
			xbmc.executebuiltin("XBMC.Notification(Error: HTTPError ,Please try again.)")
			return
		except socket.timeout, e:
			er = True
			addon_log('socket.timeout %s ' %e)
			xbmc.executebuiltin("XBMC.Notification(Error: socket.timeout ,Check your connection and try again.)")
			return
		except urllib2.URLError, e:
			er = True
			if hasattr(e,'reason') and isinstance(e.reason, socket.timeout):
				addon_log('urllib2.URLError Timeout %s ' %e.reason)
				xbmc.executebuiltin("XBMC.Notification(Error: Timeout ,Check your connection and try again.)")
				return
			elif hasattr(e, 'code'):
				addon_log('urllib2.URLError %s ' %e.code)
				xbmc.executebuiltin("XBMC.Notification(Error: URLError. Please try again, %s)" %e.code)
				return
	if er == False:
		addon_log ('er == False')
		soup = BeautifulSoup(contents)
		MovieSS22 = soup.find("div", {"id":"MovieSS22"})
		moviename = ''
		movielink = ''
		movieimage = ''
		for tag in MovieSS22:
			for line in str(tag).splitlines():
				if 'img src=' in line:
					movieimage = re.search(r'src="[^"]+"',line)
					movieimage = movieimage.group(0)[5:-1]
					#addon_log(movieimage)
				elif 'mask3' in line:
					movielink = re.search(r'href="[^"]+"',line)
					movielink = 'http://mobile.iranproud.net:8080'+movielink.group(0)[6:-1]
					#addon_log(movielink)
				elif 'SSh3' in line:
					moviename = re.search(r'"SSh3">.+<[/]div>',line)
					moviename = moviename.group(0)[7:-6]
					#addon_log(moviename)
			if moviename!='' or movielink!='' or movieimage!='':
				addDir(moviename,movielink,986,movieimage,fanart,'','','','','source')
			moviename=''
			movielink=''
			movieimage=''
	else:
		addon_log ('er == True')
		soup = BeautifulSoup(contents)
		MOVSS1 = soup.find("div", {"id":"MOVSS1"})
		for tag in MOVSS1:
			if 'href' in str(tag):
				movielink = re.search(r'href="[^"]+"',str(tag))
				movielink = 'http://persiairptv.strangled.net'+movielink.group(0)[6:-1]
				movieimage = re.search(r'src="[^"]+"',str(tag))
				movieimage = movieimage.group(0)[5:-1]
				moviename = re.search(r'thumbs[/].+_thumb.',str(tag))
				moviename = moviename.group(0)[7:-7].replace('_',' ')
				addDir(moviename,movielink,986,movieimage,fanart,'','','','','source')
	xbmcplugin.endOfDirectory(int(sys.argv[1]))
	
def IranProudSearch():
	addon_log('Im in IranProudSearch')
	kb = xbmc.Keyboard('default', 'heading', True)
	kb.setDefault('')
	kb.setHeading('IranProud Search - Enter A Movie Or Series Name...')
	kb.setHiddenInput(False)
	kb.doModal()
	if (kb.isConfirmed()):
		searchedtext = kb.getText()
		if searchedtext == '' or searchedtext == ' ' or searchedtext == '  ':
			return
		else:
			addon_log("Searched Text : %s" % searchedtext)
			import random
			UAList = ["Mozilla/5.0 (iPhone; CPU iPhone OS 9_2 like Mac OS X) AppleWebKit/601.1 (KHTML, like Gecko) CriOS/47.0.2526.70 Mobile/13C71 Safari/601.1.46","Mozilla/5.0 (Linux; U; Android 4.4.4; Nexus 5 Build/KTU84P) AppleWebkit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30","Mozilla/5.0 (Linux; U; Tizen 2.0; en-us) AppleWebKit/537.1 (KHTML, like Gecko) Mobile TizenBrowser/2.0","Mozilla/5.0 (Android 4.4; Mobile; rv:18.0) Gecko/18.0 Firefox/18.0"]
			ua = random.choice(UAList)
			headers = {
			"Connection" : "close",  # another way to cover tracks
			"User-Agent" : ua}
			request = urllib2.Request('http://mobile.iranproud.net:8080/search?page=search&searchField='+searchedtext, headers=headers)
			try:
				contents = urllib2.urlopen(request,timeout = 10).read()
			except socket_error as e:
				if e.errno != errno.ECONNREFUSED:
					addon_log('socket_error happened ECONNREFUSED')
					xbmc.executebuiltin("XBMC.Notification(Socket Error: ECONNREFUSED ,Check your connection and try again.)")
					return
				else:
					addon_log('socket_error happened UNKNOWN')
					xbmc.executebuiltin("XBMC.Notification(Socket Error: UNKNOWN ,Check your connection and try again.)")
					return
			except urllib2.HTTPError as e:
				addon_log('HTTPError : %s. We failed connecting to IranProud.' %e.code)
				xbmc.executebuiltin("XBMC.Notification(Error: HTTPError ,Please try again.)")
				return
			except socket.timeout, e:
				addon_log('socket.timeout %s ' %e)
				xbmc.executebuiltin("XBMC.Notification(Error: socket.timeout ,Check your connection and try again.)")
				return
			except urllib2.URLError, e:
				if hasattr(e,'reason') and isinstance(e.reason, socket.timeout):
					addon_log('urllib2.URLError Timeout %s ' %e.reason)
					xbmc.executebuiltin("XBMC.Notification(Error: Timeout ,Check your connection and try again.)")
					return
				elif hasattr(e, 'code'):
					addon_log('urllib2.URLError %s ' %e.code)
					xbmc.executebuiltin("XBMC.Notification(Error: URLError. Please try again, %s)" %e.code)
					return
				else:
					# reraise the original error
					raise
			addDir('Your Search Result For [COLOR yellow]%s[/COLOR] :'%searchedtext,'',0,artpath+'iranproudsearch.jpg',fanart,'','','','','source')
			match = re.findall(r'<div class="divBordera*.+\n.+\n.+\n.+\n.+\n', contents)
			sname=''
			if match:
				try:
					for item in match:
						if '"TitrSS">MUSIC</div>' in item : break
						for line in item.splitlines():
							#addon_log('line[33:40] : %s ' % line[33:40])
							if '"TitrSS">MUSIC</div>' in line : break
							if 'img' in line and '#' not in line:
								simg = re.search(r'http:.+[.]jpg', line)
								if simg:
									simg = simg.group(0)
								else:
									simg = re.search(r'http:.+[.]png', line)
									if simg:
										simg = simg.group(0)
									else:simg =''
								slink = "http://mobile.iranproud.net:8080" + line[33:line.find('" target=')]
								if 'sicvideos' in line[33:line.find('" target=')]:
									slink = "http://mobile.iranproud.net:8080/" + line[33:line.find('" target=')]
								if '/shows/' in line[33:line.find('" target=')]:
									slink = slink[0:slink.find('"')]
								if '/iran-1' in line[33:40]:
									sgenre = 'MOVIES'
								elif 'musicvi' in line[33:40]:
									sgenre = 'MUSIC VIDEOS'
								elif 'series' in line[33:40]:
									sgenre = 'TV SERIES'
								elif 'shows' in line[33:40]:
									sgenre = 'SHOWS'
							if 'SSh3' in line or 'SSh2' in line or 'SSh1' in line or 'SSh1M' in line:
								sname =  re.search(r'>.+<', line)
								sname = sname.group(0)[1:-1]
						if sname == 'MUSIC':break
						addon_log('sname : %s ' % sname)
						addon_log('slink : %s ' % slink)
						addon_log('simg : %s ' % simg)
						if sgenre == 'TV SERIES':
							addDir('[COLOR deepskyblue]%s[/COLOR] : [COLOR white][B]%s[/B][/COLOR]'%(sgenre,sname),slink,985,simg,fanart,'','','','','source')
						elif sgenre == 'MUSIC VIDEOS':
							addDir('[COLOR deepskyblue]%s[/COLOR] : [COLOR white][B]%s[/B][/COLOR]'%(sgenre,sname),slink,986,simg,fanart,'','','','','source')
						elif sgenre == 'MOVIES':
							addDir('[COLOR deepskyblue]%s[/COLOR] : [COLOR white][B]%s[/B][/COLOR]'%(sgenre,sname),slink,986,simg,fanart,'','','','','source')
						elif sgenre == 'SHOWS':
							addDir('[COLOR deepskyblue]%s[/COLOR] : [COLOR white][B]%s[/B][/COLOR]'%(sgenre,sname),slink,985,simg,fanart,'','','','','source')
				except:
					xbmc.executebuiltin("XBMC.Notification(Search : Nothing has been found,Try with a different word.)")
					addon_log('Search : Nothing has been found,Try with a different word.')
					return

			xbmcplugin.endOfDirectory(int(sys.argv[1]))
		
def GetRandomM3U():
	global isitrandom
	isitrandom = True
	global serverNumber
	serverNumber = 0
	import random
	import datetime
	import time
	today = datetime.date.today()
	todaydate = today.strftime("%d/%m/%Y")
	todaydatetuple = time.strptime(todaydate,"%d/%m/%Y")
	todaytime = datetime.datetime.now()
	todaytimetuple = todaytime.timetuple()
	try:
		cachefile = open(home2+'cache.txt','r')
		cachefilecontent = cachefile.readlines()
		cachedate = cachefilecontent[0]
		cachedatetuple = time.strptime(cachedate,"%d/%m/%Y\n")
		cachetime = cachefilecontent[1]
		cachetimetuple = time.strptime(cachetime,"%H:%M:%S\n")
		cachefile.close()
		addon_log('CacheDate : %s / %s / %s' % (cachedatetuple.tm_year,cachedatetuple.tm_mon,cachedatetuple.tm_mday))
		addon_log('CacheTime : %s : %s : %s' % (cachetimetuple.tm_hour,cachetimetuple.tm_min,cachetimetuple.tm_sec))
	except:
		pass
	addon_log('TodayDate : %s / %s / %s' % (todaydatetuple.tm_year,todaydatetuple.tm_mon,todaydatetuple.tm_mday))
	addon_log('TodayTime : %s : %s : %s' % (todaytimetuple.tm_hour,todaytimetuple.tm_min,todaytimetuple.tm_sec))
	ValidM3ULink = 0
	try:
		if todaydatetuple.tm_year == cachedatetuple.tm_year and todaydatetuple.tm_mon == cachedatetuple.tm_mon and todaydatetuple.tm_mday == cachedatetuple.tm_mday and todaytimetuple.tm_hour - cachetimetuple.tm_hour < 1:
			#agar sa'ate separi shode kochek tar az 1 bood va tarikh yeki bood:
			addon_log('Loading IPTV Random Channels from cache.')
			with open(home2+'cache.txt', 'r') as f:
				for line in f:
					if 'http' in line:
						chk = checkUrl(line)
						if chk == True:
							ValidM3ULink = ValidM3ULink + 1
							serverNumber = serverNumber + 1
							getData(line,FANART)
			serverNumber = 0
			addon_log('Loaded %s working m3u link from Cache.' % ValidM3ULink)
		else:
			raise
	except:
		try:
			addon_log('Loading IPTV Random Channels from Internet and Caching them.')
			UAList = ["Mozilla/5.0 (Windows; U; Windows NT 6.1; de; rv:1.9.1.16) Gecko/20101130 AskTbMYC/3.9.1.14019 Firefox/3.5.16","Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.1.16) Gecko/20101130 AskTbPLTV5/3.8.0.12304 Firefox/3.5.16 (.NET CLR 3.5.30729)","Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.9.1.16) Gecko/20101130 Firefox/3.5.16 GTB7.1 (.NET CLR 3.5.30729)","Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.9.1.16) Gecko/20101130 Firefox/3.5.16 GTB7.1","Mozilla/5.0 (X11; U; Linux x86_64; it; rv:1.9.1.15) Gecko/20101027 Fedora/3.5.15-1.fc12 Firefox/3.5.15","Mozilla/5.0 (X11; U; Linux i686; en-GB; rv:1.9.1.15) Gecko/20101027 Fedora/3.5.15-1.fc12 Firefox/3.5.15","Mozilla/5.0 (Windows; U; Windows NT 5.1; hu; rv:1.9.1.11) Gecko/20100701 Firefox/3.5.11","Mozilla/5.0 (iPhone; U; CPU iPhone OS 4_2_1 like Mac OS X; it-it) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8C148a Safari/6533.18.5","Mozilla/5.0 (iPhone; U; CPU iPhone OS 4_2_1 like Mac OS X; fr) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8C148a Safari/6533.18.5","Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.1.10) Gecko/20100504 Firefox/3.5.11 (.NET CLR 3.5.30729)","Mozilla/5.0 (X11; U; Linux x86_64; de; rv:1.9.1.10) Gecko/20100506 SUSE/3.5.10-0.1.1 Firefox/3.5.10","Mozilla/5.0 (Windows; U; Windows NT 6.0; en-GB; rv:1.9.1.10) Gecko/20100504 Firefox/3.5.10 GTB7.0 ( .NET CLR 3.5.30729)","Mozilla/5.0 (X11; U; Linux x86_64; rv:1.9.1.1) Gecko/20090716 Linux Firefox/3.5.1","Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.3) Gecko/20100524 Firefox/3.5.1","Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090716 Linux Mint/7 (Gloria) Firefox/3.5.1","Mozilla/5.0 (X11; U; Linux i686; en-US) AppleWebKit/534.7 (KHTML, like Gecko) Chrome/7.0.517.24 Safari/534.7","Mozilla/5.0 (X11; U; Linux x86_64; fr-FR) AppleWebKit/534.7 (KHTML, like Gecko) Chrome/7.0.514.0 Safari/534.7","Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.7 (KHTML, like Gecko) Chrome/7.0.514.0 Safari/534.7","Mozilla/5.0 (Windows; U; Windows NT 6.0; ja-JP) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27","Mozilla/5.0 (Macintosh; U; PPC Mac OS X 10_5_8; ja-jp) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27","Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_6; sv-se) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27"]
			ua = random.choice(UAList)
			headers = {
			"Connection" : "close",  # another way to cover tracks
			"User-Agent" : ua}
			#website = 'http://www.oneplaylist.eu.pn/'
			#website = 'http://www.database.eu.pn/'
			website = 'http://www.oneplaylist.space/'
			request = urllib2.Request(website, headers=headers)
			response = urllib2.urlopen(request).read()
			match = re.findall(r'(http:[/][/].+m3u[^8])',response)
			m3ulinksCount = 0
			ValidM3ULink = 0
			if match:
				cachefile = open(home2+'cache.txt' , 'w')
				cachefile.write(todaydate+'\n')
				cachefile.write('%s:%s:%s\n' % (todaytimetuple.tm_hour,todaytimetuple.tm_min,todaytimetuple.tm_sec))
				cachefile.close()
				serverlist = []
				for m3u in match:
					duplicate = False
					if m3u[:-1].count('http://') >= 2: continue
					for item in serverlist:
						if m3u[:25] in item:
							addon_log('Reduplicative server founded, Passing to next link.')
							duplicate = True
							break
					if duplicate == False :
						serverlist.append(m3u[:-1])
						m3ulinksCount = m3ulinksCount + 1
						chk = checkUrl(m3u[:-1])
						if chk == True:
							ValidM3ULink = ValidM3ULink + 1
							serverNumber = serverNumber + 1
							cachefile = open(home2+'cache.txt' , 'a')
							cachefile.write(m3u[:-1] + '\n')
							cachefile.close()
							getData(m3u[:-1],FANART)
				serverNumber = 0
				addon_log('Found %s m3u links, Awesome.' % m3ulinksCount)
				addon_log('From %s m3u links that i found , %s of them are working.' % (m3ulinksCount , ValidM3ULink))
				addon_log('Working links has been added to cache.')
			else:
				addon_log('!!!!!!!!!!! no m3u link has been found')
		except:
			xbmc.executebuiltin("XBMC.Notification(Server not accessible.,Loading from Cache.)")
			addon_log('!!! Problem connecting to source web site to update channel list.')
			addon_log('!!! Loading old channels from Cache.')
			ValidM3ULink = 0
			with open(home2+'cache.txt', 'r') as f:
				for line in f:
					if 'http' in line:
						chk = checkUrl(line)
						if chk == True:
							ValidM3ULink = ValidM3ULink + 1
							serverNumber = serverNumber + 1
							getData(line,FANART)
			serverNumber = 0
			addon_log('Loaded %s working m3u link from Cache.' % ValidM3ULink)
			if ValidM3ULink == 0 : addon_log('!!! Cache file is empty.')
	isitrandom = False
	xbmcplugin.endOfDirectory(int(sys.argv[1]))
def playsetresolved(url,name,iconimage,setresolved=True,reg=None):
    print url
    if setresolved:
        setres=True
        if '$$LSDirect$$' in url:
            url=url.replace('$$LSDirect$$','')
            setres=False
        if reg and 'notplayable' in reg:
            setres=False

        liz = xbmcgui.ListItem(name, iconImage=iconimage)
        liz.setInfo(type='Video', infoLabels={'Title':name})
        liz.setProperty("IsPlayable","true")
        liz.setPath(url)
        if not setres:
            xbmc.Player().play(url)
        else:
            xbmcplugin.setResolvedUrl(int(sys.argv[1]), True, liz)
           
    else:
        xbmc.executebuiltin('XBMC.RunPlugin('+url+')')

##not a generic implemenation as it needs to convert            
def d2x(d, root="root",nested=0):

    op = lambda tag: '<' + tag + '>'
    cl = lambda tag: '</' + tag + '>\n'

    ml = lambda v,xml: xml + op(key) + str(v) + cl(key)
    xml = op(root) + '\n' if root else ""

    for key,vl in d.iteritems():
        vtype = type(vl)
        if nested==0: key='regex' #enforcing all top level tags to be named as regex
        if vtype is list: 
            for v in vl:
                v=escape(v)
                xml = ml(v,xml)         
        
        if vtype is dict: 
            xml = ml('\n' + d2x(vl,None,nested+1),xml)         
        if vtype is not list and vtype is not dict: 
            if not vl is None: vl=escape(vl)
            #print repr(vl)
            if vl is None:
                xml = ml(vl,xml)
            else:
                #xml = ml(escape(vl.encode("utf-8")),xml)
                xml = ml(vl.encode("utf-8"),xml)

    xml += cl(root) if root else ""

    return xml
xbmcplugin.setContent(int(sys.argv[1]), 'movies')

try:
    xbmcplugin.addSortMethod(int(sys.argv[1]), xbmcplugin.SORT_METHOD_UNSORTED)
except:
    pass
try:
    xbmcplugin.addSortMethod(int(sys.argv[1]), xbmcplugin.SORT_METHOD_LABEL)
except:
    pass
try:
    xbmcplugin.addSortMethod(int(sys.argv[1]), xbmcplugin.SORT_METHOD_DATE)
except:
    pass
try:
    xbmcplugin.addSortMethod(int(sys.argv[1]), xbmcplugin.SORT_METHOD_GENRE)
except:
    pass

params=get_params()

url=None
name=None
mode=None
iconimage=None
fanart=FANART
playlist=None
channelid=None
fav_mode=None
regexs=None
title=None
usurl=None

try:channelid=urllib.unquote_plus(params["channelid"])
except:pass
try:
    url=urllib.unquote_plus(params["url"]).decode('utf-8')
except:
    pass
try:
    name=urllib.unquote_plus(params["name"])
except:
    pass
try:
    iconimage=urllib.unquote_plus(params["iconimage"])
except:
    pass
try:
    fanart=urllib.unquote_plus(params["fanart"])
except:
    pass
try:
    mode=int(params["mode"])
except:
    pass
try:
    playlist=eval(urllib.unquote_plus(params["playlist"]).replace('||',','))
except:
    pass
try:
    fav_mode=int(params["fav_mode"])
except:
    pass
try:
    regexs=params["regexs"]
except:
    pass
playitem=''
try:
    playitem=urllib.unquote_plus(params["playitem"])
except:
    pass
    
addon_log("Mode: "+str(mode))


if not url is None:
    addon_log("URL: "+str(url.encode('utf-8')))
addon_log("Name: "+str(name))

if not playitem =='':
    s=getSoup('',data=playitem)
    name,url,regexs=getItems(s,None,dontLink=True)
    mode=117 
if mode==None:
	with open(source_file, 'r') as myfile:
		SOURCES=myfile.read()
	addon_log("getSources")
	getSources(SOURCES)
	xbmcplugin.endOfDirectory(int(sys.argv[1]))

elif mode==0:
	pass

elif mode==1:
    addon_log("getData")
    data=None
    if regexs:
        data=getRegexParsed(regexs, url)
        url=''
        #create xml here
    getData(url,fanart,data)
    if name != 'Movies':
        xbmc.executebuiltin("Container.SetViewMode(500)")
    xbmcplugin.endOfDirectory(int(sys.argv[1]))

elif mode==2:
    addon_log("getChannelItems")
    getChannelItems(name,url,fanart)
    xbmcplugin.endOfDirectory(int(sys.argv[1]))

elif mode==3:
    addon_log("getSubChannelItems")
    getSubChannelItems(name,url,fanart)
    xbmcplugin.endOfDirectory(int(sys.argv[1]))

elif mode==12:
    addon_log("setResolvedUrl")
    if not url.startswith("plugin://plugin"):
        setres=True
        if '$$LSDirect$$' in url:
            url=url.replace('$$LSDirect$$','')
            setres=False
        item = xbmcgui.ListItem(path=url)
        if not setres:
            addon_log('mode 12 if not setres')
            xbmc.Player().play(url)
        else: 
            addon_log('mode 12 if setres, calling setResolvedUrl')
            xbmcplugin.setResolvedUrl(int(sys.argv[1]), True, item)
    else:
        xbmc.executebuiltin('XBMC.RunPlugin('+url+')')


elif mode==13:
    addon_log("play_playlist")
    play_playlist(name, playlist)

elif mode==14:
    addon_log("get_xml_database")
    get_xml_database(url)
    xbmcplugin.endOfDirectory(int(sys.argv[1]))

elif mode==15:
    addon_log("browse_xml_database")
    get_xml_database(url, True)
    xbmcplugin.endOfDirectory(int(sys.argv[1]))

elif mode==17 or mode==117:
    addon_log("getRegexParsed")

    data=None
    if regexs and 'listrepeat' in urllib.unquote_plus(regexs):
        listrepeat,ret,m,regexs =getRegexParsed(regexs, url)
        d=''
        regexname=m['name']
        existing_list=regexs.pop(regexname)
        url=''
        import copy
        ln=''
        rnumber=0
        for obj in ret:
            try:
                rnumber+=1
                newcopy=copy.deepcopy(regexs)
                listrepeatT=listrepeat
                i=0
                for i in range(len(obj)):
                    if len(newcopy)>0:
                        for the_keyO, the_valueO in newcopy.iteritems():
                            if the_valueO is not None:
                                for the_key, the_value in the_valueO.iteritems():
                                    if the_value is not None:
                                        if type(the_value) is dict:
                                            for the_keyl, the_valuel in the_value.iteritems():
                                                if the_valuel is not None:
                                                    val=None
                                                    if isinstance(obj,tuple):                                                    
                                                        try:
                                                           val= obj[i].decode('utf-8') 
                                                        except: 
                                                            val= obj[i] 
                                                    else:
                                                        try:
                                                            val= obj.decode('utf-8') 
                                                        except:
                                                            val= obj
                                                    
                                                    if '[' + regexname+'.param'+str(i+1) + '][DE]' in the_valuel:
                                                        the_valuel=the_valuel.replace('[' + regexname+'.param'+str(i+1) + '][DE]', unescape(val))
                                                    the_value[the_keyl]=the_valuel.replace('[' + regexname+'.param'+str(i+1) + ']', val)
                                                    
                                        else:
                                            val=None
                                            if isinstance(obj,tuple):
                                                try:
                                                     val=obj[i].decode('utf-8') 
                                                except:
                                                    val=obj[i] 
                                            else:
                                                try:
                                                    val= obj.decode('utf-8') 
                                                except:
                                                    val= obj
                                            if '[' + regexname+'.param'+str(i+1) + '][DE]' in the_value:
                                                the_value=the_value.replace('[' + regexname+'.param'+str(i+1) + '][DE]', unescape(val))

                                            the_valueO[the_key]=the_value.replace('[' + regexname+'.param'+str(i+1) + ']', val)

                    val=None
                    if isinstance(obj,tuple):
                        try:
                            val=obj[i].decode('utf-8')
                        except:
                            val=obj[i]
                    else:
                        try:
                            val=obj.decode('utf-8')
                        except: 
                            val=obj
                    if '[' + regexname+'.param'+str(i+1) + '][DE]' in listrepeatT:
                        listrepeatT=listrepeatT.replace('[' + regexname+'.param'+str(i+1) + '][DE]',val)
                    listrepeatT=listrepeatT.replace('[' + regexname+'.param'+str(i+1) + ']',escape(val))
#                    print listrepeatT
                listrepeatT=listrepeatT.replace('[' + regexname+'.param'+str(0) + ']',str(rnumber)) 
                
#                print 'new regex list', repr(newcopy), repr(listrepeatT)
#                addLink(listlinkT,listtitleT.encode('utf-8', 'ignore'),listthumbnailT,'','','','',True,None,newcopy, len(ret))
                regex_xml=''
#                print 'newcopy',newcopy
                if len(newcopy)>0:
                    regex_xml=d2x(newcopy,'lsproroot')
                    regex_xml=regex_xml.split('<lsproroot>')[1].split('</lsproroot')[0]
               
                try:
                    ln+='\n<item>%s\n%s</item>'%(listrepeatT,regex_xml)
                except: ln+='\n<item>%s\n%s</item>'%(listrepeatT.encode("utf-8"),regex_xml)
            except: traceback.print_exc(file=sys.stdout)
#            print repr(ln)
#            print newcopy
                
#            ln+='</item>'
        
        addon_log(repr(ln))
        getData('','',ln)
        xbmcplugin.endOfDirectory(int(sys.argv[1]))
    else:
        url,setresolved = getRegexParsed(regexs, url)
        #print repr(url),setresolved,'imhere'
        if url:
            if '$PLAYERPROXY$=' in url:
                url,proxy=url.split('$PLAYERPROXY$=')
                print 'proxy',proxy
                #Jairox mod for proxy auth
                proxyuser = None
                proxypass = None
                if len(proxy) > 0 and '@' in proxy:
                    proxy = proxy.split(':')
                    proxyuser = proxy[0]
                    proxypass = proxy[1].split('@')[0]
                    proxyip = proxy[1].split('@')[1]
                    port = proxy[2]
                else:
                    proxyip,port=proxy.split(':')

                playmediawithproxy(url,name,iconimage,proxyip,port, proxyuser,proxypass) #jairox
            else:
                playsetresolved(url,name,iconimage,setresolved,regexs)
        else:
            xbmc.executebuiltin("XBMC.Notification(ParsiLand,Failed to extract regex. - "+"this"+",4000,"+icon+")")
elif mode==53:
    addon_log("Requesting JSON-RPC Items")
    pluginquerybyJSON(url)
elif mode==1338:
	GetRandomM3U()
	xbmcplugin.endOfDirectory(int(sys.argv[1]))
elif mode==98: #IranProud manin menu
	addDir('Search','',987,artpath+'iranproudsearch.jpg',fanart,'','','','','source')
	addDir('Series','',981,artpath+'iranproudseries.jpg',fanart,'','','','','source')
	addDir('Shows','',990,artpath+'iranproudshows.jpg',fanart,'','','','','source')
	addDir('Movies','',998,artpath+'iranproudmovies.jpg',fanart,'','','','','source')
	xbmcplugin.endOfDirectory(int(sys.argv[1]))
elif mode==981: #series
	addDir('Drama Series','',982,artpath+'iranprouddramaseries.jpg',fanart,'','','','','source')
	addDir('Comedy Series','',982,artpath+'iranproudcomedyseries.jpg',fanart,'','','','','source')
	addDir('Action Series','',982,artpath+'iranproudactionseries.jpg',fanart,'','','','','source')
	addDir('Cartoon Series','',982,artpath+'iranproudcartoonseries.jpg',fanart,'','','','','source')
	xbmcplugin.endOfDirectory(int(sys.argv[1]))
elif mode==982:
	IranProudSeriesList(name)
elif mode==985:
	IranProudSeriesEpisodes(url)
elif mode==986:
	IranProudSeriesGetEpisode(url)
elif mode==987:
	IranProudSearch()
elif mode==990: #shows
	addDir('Reality Shows','',991,artpath+'iranproudrealityshow.jpg',fanart,'','','','','source')
	addDir('TV & Cinema Shows','',991,artpath+'iranproudtvcinemashow.jpg',fanart,'','','','','source')
	addDir('Health & Beauty Shows','',991,artpath+'iranproudhealthshow.jpg',fanart,'','','','','source')
	addDir('Documentry Shows','',991,artpath+'iranprouddocumentryshow.jpg',fanart,'','','','','source')
	addDir('Talk Shows Shows','',991,artpath+'iranproudtalkshow.jpg',fanart,'','','','','source')
	addDir('Comedy Shows','',991,artpath+'iranproudcomedyshow.jpg',fanart,'','','','','source')
	addDir('Sports Shows','',991,artpath+'iranproudsportshow.jpg',fanart,'','','','','source')
	xbmcplugin.endOfDirectory(int(sys.argv[1]))
elif mode==991:
	IranProudShowsList(name)
elif mode==998: #movies
	addDir('New Movies','',999,artpath+'iranproudnewmovies.jpg',fanart,'','','','','source')
	addDir('Recommended Movies (random)','',999,artpath+'iranproudrecommendedmovies.jpg',fanart,'','','','','source')
	addDir('Comedy Movies','',999,artpath+'iranproudcomedymovies.jpg',fanart,'','','','','source')
	addDir('Drama Movies','',999,artpath+'iranprouddramamovies.jpg',fanart,'','','','','source')
	addDir('Action Movies','',999,artpath+'iranproudactionmovies.jpg',fanart,'','','','','source')
	addDir('Classic Movies','',999,artpath+'iranproudclassicmovies.jpg',fanart,'','','','','source')
	addDir('TV & Cinema Movies','',999,artpath+'iranproudtvcinemamovies.jpg',fanart,'','','','','source')
	xbmcplugin.endOfDirectory(int(sys.argv[1]))
elif mode==999:
	if 'New Movies' in name:
		IranProudMoviesNewReleases()
	elif 'Recommended Movies' in name:
		IranProudMoviesMostPopular()
	else:
		IranProudMoviesCat(name)
elif mode==9990:
	IranProudPlayMovie(url)
elif mode==100:
	myurl=urllib.unquote(url).decode('utf8')
	myurl=myurl[37:]
	myurl=myurl.split('&amp;')
	myurl=myurl[0]
	if checkUrl(myurl):
		addon_log('Selected channel is alive')
		playmedia(url)
	else:
		xbmc.executebuiltin("XBMC.Notification(This channel or its server is offline.,Please try other channels.)")
		addon_log('checkUrl returned false!. This channel or its server is offline.,Please try other channels.')
		xbmc.sleep(200)
elif mode==90:
	addDir('EuroSport 1','http://www.cast4u.tv/embed.php?v=euro1&vw=620&vh=490',901,artpath+'eurosport.jpg',fanart,'','','','','source')
	addDir('EuroSport 2','http://www.cast4u.tv/embed.php?v=euro2&vw=620&vh=490',901,artpath+'eurosport2.jpg',fanart,'','','','','source')
	addDir('SkySports 1','http://www.cast4u.tv/embedcr.php?v=skys1&vw=620&vh=490',901,artpath+'skysports1.jpg',fanart,'','','','','source')
	addDir('SkySports 2','http://www.cast4u.tv/embedcr.php?v=skys2&vw=620&vh=490',901,artpath+'skysports2.jpg',fanart,'','','','','source')
	addDir('SkySports 3','http://www.cast4u.tv/embedcr.php?v=skys3&vw=620&vh=490',901,artpath+'skysports3.jpg',fanart,'','','','','source')
	addDir('SkySports 4','http://www.cast4u.tv/embedcr.php?v=skys4&vw=620&vh=490',901,artpath+'skysports4.jpg',fanart,'','','','','source')
	addDir('SkySports 5','http://www.cast4u.tv/embedcr.php?v=skys5&vw=620&vh=490',901,artpath+'skysports5.jpg',fanart,'','','','','source')
	addDir('SkySports News','http://www.cast4u.tv/embed.php?v=skyspnz&vw=620&vh=490',901,artpath+'skysportsnews.jpg',fanart,'','','','','source')
	addDir('BT Sport 1','http://www.cast4u.tv/embedhd.php?v=bt1&vw=620&vh=490',901,artpath+'btsport1.jpg',fanart,'','','','','source')
	addDir('BT Sport 2','http://www.cast4u.tv/embedhd.php?v=bt2&vw=620&vh=490',901,artpath+'btsport2.jpg',fanart,'','','','','source')
	addDir('Premier Sports','http://www.cast4u.tv/embed.php?v=premier&vw=620&vh=490',901,artpath+'premiersports.jpg',fanart,'','','','','source')
	addDir('WWE','http://www.cast4u.tv/embed.php?v=wwe&vw=620&vh=490',901,artpath+'wwe.jpg',fanart,'','','','','source')
	xbmcplugin.endOfDirectory(int(sys.argv[1]))
elif mode==901:
	UA={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}
	swfUrl='http://www.cast4u.tv/myplayer/jwplayer.flash.swf'
	req = urllib2.Request(url,headers=UA)
	try:
		response = urllib2.urlopen(req, timeout=20)
		decoded = response.read()
		response.close()
	except:
		decoded=''
	if decoded == '':
		print 'script failed , decoded is empty'
	else:
		# find url function names:
		fnames = re.compile('file: (.*?)\(\) \+ \'/\' \+ (.*?)\(\)').findall(decoded)
		token = re.search('securetoken: (.*?)\n',decoded)
		if fnames:
			fnames=fnames[0]
			stream=[]
			authen=''
			for fname in fnames:
				idx1 = decoded.find('function '+fname)
				idx2 = decoded[idx1:].find('}')
				tmp = decoded[idx1:idx1+idx2]
				s=re.search('(\[.*?\])',tmp).group(1)
				stream.append(''.join(eval(s)).replace('\\',''))
				# look for auth code
				cod=re.search('join\(\"\"\) \+ (.*?).join\(\"\"\)',tmp)
				if cod and authen=='':
				   authen = re.search(cod.group(1)+' = (\[.*?\])',decoded).group(1)
				   authen = ''.join(eval(authen))
				
			video_url = stream[0] + authen +'/'+ stream[1] + ' token=%XB00(nKH@#. swfUrl='+swfUrl  + ' flashver=WIN\\2021,0,0,242 swfVfy=1 live=1 timeout=20 pageUrl='+url
			addon_log(video_url)
			playmedia(video_url)
