CROC_GETAVATAR = 0x21
CROC_GETCHAN   = 0x22
CROC_GETMSGS   = 0x23
CROC_SENDMSG   = 0x24

GETCHAN_CMD = ''
GETCHAN_CMD += 'curl -v '
GETCHAN_CMD += '-H "authorization: {DISCORD_TOKEN}" '
GETCHAN_CMD += '-H "User-Agent: Crocodile (https://shekihs.space, v0.1)" '
GETCHAN_CMD += '-H "Content-Type: application/json" '
GETCHAN_CMD += '-X GET '
GETCHAN_CMD += 'https://discordapp.com/api/channels/{DISCORD_CHANNEL} 2>/dev/null'

SENDMSG_CMD = ''
SENDMSG_CMD += 'curl -v '
SENDMSG_CMD += '-H "authorization: {DISCORD_TOKEN}" '
SENDMSG_CMD += '-H "User-Agent: Crocodile (https://shekihs.space, v0.1)" '
SENDMSG_CMD += '-H "Content-Type: application/json" '
SENDMSG_CMD += '-X POST '
SENDMSG_CMD += '-d \'{"content":"{DISCORD_MSG}"}\' '
SENDMSG_CMD += 'https://discordapp.com/api/channels/{DISCORD_CHANNEL}/messages 2>/dev/null'

def crocodile(data):
    if data == CROC_GETAVATAR:
        CrocGetAvatar()
    if data == CROC_GETCHAN:
        CrocGetChan()
    if data == CROC_GETMSGS:
        CrocGetMsgs()
    if data == CROC_SENDMSG:
        CrocSendMsg()

def HGBD_seek(offset=0, seek=None):
    if seek is None:
        seek = os.SEEK_SET
    os.lseek(HGBD, offset, seek)

def HGBD_write(data, offset=0, seek=None):
    HGBD_seek(offset, seek)
    os.write(HGBD, data)

def run_cmd(cmd):
    resp = subprocess.Popen(
        cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE
    ).communicate()[0]

    return resp


def CrocGetAvatar():
    HGBD_seek()
    HGBD_PARAM_BUF = os.read(HGBD,BLK_SIZE)
    r_author_id = HGBD_PARAM_BUF[:HGBD_PARAM_BUF.find('\x00')]
    r_avatar = HGBD_PARAM_BUF[64:HGBD_PARAM_BUF.find('\x00',64)]
    tmp_bmp_file = '/tmp/' + r_avatar + '.bmp'
    resp = subprocess.Popen('wget -q -O - https://cdn.discordapp.com/avatars/' + r_author_id + '/' + r_avatar + '.png\?size=32 | gm convert - ' + tmp_bmp_file,shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE).communicate()[0]
    with open(tmp_bmp_file,"rb") as f:
        filesize = len(f.read())
    ZeroParamBuf()
    HGBD_write(str(filesize))
    HGBD_write(filedata, offset=BLK_SIZE)
    os.remove(tmp_bmp_file)
    conn.send(chr(CROC_GETAVATAR))

def CrocGetChan():
    HGBD_seek()
    HGBD_PARAM_BUF = os.read(HGBD,BLK_SIZE)
    r_token = HGBD_PARAM_BUF[:HGBD_PARAM_BUF.find('\x00')]
    r_chan_id = HGBD_PARAM_BUF[256:HGBD_PARAM_BUF.find('\x00',256)]
    chan_lmid = ''
    chan_name = ''
    chan_topic = ''
    try:
        croc_cmd = GETCHAN_CMD.format(
            DISCORD_TOKEN=r_token,
            DISCORD_CHANNEL=r_chan_id
        )
        chan_json = json.loads(run_cmd(croc_cmd))
        chan_lmid = str(chan_json['last_message_id'])
        chan_name = str(chan_json['name'])
        chan_topic = str(chan_json['topic'])
    except:
        pass
    ZeroParamBuf()
    HGBD_write(chan_name)
    HGBD_write(chan_lmid, offset=128)
    HGBD_write(chan_topic, offset=256)
    conn.send(chr(CROC_GETCHAN))

def CrocGetMsgs():
    HGBD_seek()
    HGBD_PARAM_BUF = os.read(HGBD,BLK_SIZE)
    r_token = HGBD_PARAM_BUF[:HGBD_PARAM_BUF.find('\x00')]
    r_chan_id = HGBD_PARAM_BUF[256:HGBD_PARAM_BUF.find('\x00',256)]
    msgs_cnt = 0
    ZeroParamBuf()

    try:
        croc_cmd = GETCHAN_CMD.format(
            DISCORD_TOKEN=r_token,
            DISCORD_CHANNEL=r_chan_id + '/messages',
        )
        msgs_json = json.loads(run_cmd(croc_cmd))

        msgs_cnt = len(msgs_json)
        msg_ofs = BLK_SIZE
        msgs_json.reverse()
        for msg in msgs_json:
            attachments = ''
            if 'attachments' in msg:
                for att in msg['attachments']:
                    attachments += '\n' + att['url']

            HGBD_write('\x00'*2048, offset=msg_ofs)
            HGBD_write(msg['id']+'\x00', offset=msg_ofs)
            msg_ofs += 64
            HGBD_write(msg['timestamp'][:19].replace('T',' ')+'\x00', offset=msg_ofs)
            msg_ofs += 64
            HGBD_write(msg['author']['username']+'\x00', offset=msg_ofs)
            msg_ofs += 64
            HGBD_write(str(msg['author']['id'])+'\x00', offset=msg_ofs)
            msg_ofs += 64
            HGBD_write(str(msg['author']['avatar'])+'\x00', offset=msg_ofs)
            msg_ofs += 64
            HGBD_write(msg['content'].encode('utf8')+attachments+'\x00', offset=msg_ofs)
            msg_ofs += 1024

        HGBD_write(str(msgs_cnt))
    except:
        HGBD_write("0")

    conn.send(chr(CROC_GETMSGS))

def CrocSendMsg():
    HGBD_seek()
    HGBD_PARAM_BUF = os.read(HGBD,BLK_SIZE)

    r_token = HGBD_PARAM_BUF[:HGBD_PARAM_BUF.find('\x00')]
    r_chan_id = HGBD_PARAM_BUF[256:HGBD_PARAM_BUF.find('\x00',256)]

    os.lseek(HGBD,BLK_SIZE,os.SEEK_SET)
    HGBD_MSG_BUF = os.read(HGBD,BLK_SIZE*2)
    r_msg = HGBD_MSG_BUF[:HGBD_MSG_BUF.find('\x00')]
    r_msg = r_msg.replace('\xFF','\"')
    r_msg = r_msg.replace('\'','\u0027')

    try:
        croc_cmd = SENDMSG_CMD.format(
            DISCORD_TOKEN=r_token,
            DISCORD_CHANNEL=r_chan_id,
            DISCORD_MSG=r_msg
        )
        resp = run_cmd(croc_cmd)
    except:
        pass

    ZeroParamBuf()
    conn.send(chr(CROC_SENDMSG))
