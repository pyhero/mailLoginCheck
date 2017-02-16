#!/usr/bin/env python
# coding=utf-8
#
# Author: Panda
# Update: 20160715
#
# check mail login,insecurity then notify.
import MySQLdb
import datetime
from functools import reduce
import urllib.request
import json
import socket
import smtplib
import email.mime.multipart
import email.mime.text
import time

# mail info
MAILINFO = {'from': 'yunwei@aiuv.cc',
            'passwd': '123.com',
            'smtpSer': 'smtp.qq.com',
            'to': 'tech_group@aiuv.cc'
            }

# mysql connect information
DBINFO = {'host': '10.0.0.1',
          'port': 3308,
          'user': 'mailnotify',
          'password': '123.com',
          'db': 'cmxt_log',
          'tables': ['tl_web', 'tl_imap', 'tl_smtp', 'tl_pop']
          }

# define 7 days ago
seven_days_ago = datetime.date.today() - datetime.timedelta(7)
time_since = seven_days_ago.strftime('%Y-%m-%d %H:%M:%S')

# get data from mysql
try:
    conn = MySQLdb.connect(host=DBINFO['host'],
                           user=DBINFO['user'],
                           passwd=DBINFO['password'],
                           port=DBINFO['port'],
                           db=DBINFO['db'],
                           connect_timeout=10
                           )
    cur = conn.cursor()
    accessInfo = list()
    for t in DBINFO['tables']:
        sql = "select user_id,from_ip from {} where access_time >= '{}'".format(t,time_since)
        cur.execute(sql)
        rows = list(cur.fetchall())
        accessInfo.extend(rows)
        rows.clear()
    accessInfo.sort()
    accessInfo_it = iter(accessInfo)
    cur.close()
    conn.close()
except MySQLdb.Error as e:
    print("Error %d: %s" % (e.args[0], e.args[1]))
    exit(2)

# format data to dict
members = set()         # names set
member_ip = dict()      # ips of names
members_info = dict()   # all names' ip
all_ip = dict()
while True:
    try:
        data = next(accessInfo_it)
        name = data[0]
        ipAdd = data[1]
        # add name to set,if new name clear member_ip
        if len(members) == 0:
            members.add(name)
        elif name not in members:
            members.add(name)
            member_ip.clear()
        # calc all ip to dict
        if ipAdd not in all_ip.keys():
            all_ip[ipAdd] = 1
        else:
            all_ip[ipAdd] = all_ip[ipAdd] + 1
        # one name one ip dict,all name{} in members_info
        if ipAdd not in member_ip.keys():
            member_ip[ipAdd] = 1
        else:
            member_ip[ipAdd] = member_ip[ipAdd] + 1
        members_info[name] = member_ip.copy()
    except:
        break

# calc all login times >= 50 ip as common ips,ip white list.
ip_top = sorted(all_ip.items(), key=lambda x:x[1])
ip_top.reverse()
common_ips = iter(ip_top)
cip = set()
while True:
    try:
        ip = next(common_ips)
        if ip[1] >= 50:
            cip.add(ip[0])
        else:
            break
    except:
        break

# use reduce() to merge ip
ip_calc_lst = list()
def ip_calc(x, y):
    if x[0].split('.')[0] == y[0].split('.')[0]:
        if tuple(x) in ip_calc_lst:
            ip_calc_lst.remove(tuple(x))
        x[1] = x[1] + y[1]
        ip_calc_lst.append(tuple(x))
        return x
    else:
        ip_calc_lst.append(tuple(y))
        return y

# resolv IP to city
def resolvIP(ip):
    try:
        url = "http://ip.taobao.com/service/getIpInfo.php?ip={}".format(ip)
        data = json.loads((urllib.request.urlopen(url).read()).decode())
        if data['code'] == 0:
            city = data['data']['city']
        else:
            city = 'Error'
        if not city:
            city = data['data']['country']
        return city
    except socket.timeout:
        city = "Timeout"
        return city
    except urllib.error.URLError as e:
        city = "Unknow"
        return city

# calc login ip for everyone,and in one dict
unusual_user = dict()
member_it = iter(members)
while True:
    try:
        name = next(member_it)
        member_info = sorted(members_info[name].items(), key=lambda x:x[0])
        member_info_lst = [list(x) for x in member_info]
        if len(member_info_lst) >= 2:
            reduce(ip_calc,member_info_lst)
            common_ip = list((sorted(ip_calc_lst, key=lambda x:x[1]))[-1])
            if common_ip[1] > 7:
                common_city = resolvIP(common_ip[0])
                common_ip.append(common_city)
                unusual = list()
                for item in ip_calc_lst:
                    if (item[1] < 5) and (item[1] not in cip):
                        unusual_city = resolvIP(item[0])
                        if unusual_city != common_city:
                            itemlst = list(item)
                            itemlst.append(unusual_city)
                            unusual.append(itemlst)
                if unusual:
                    unusual_user[name] = [common_ip,unusual]
            ip_calc_lst.clear()
    except:
        break

# mailling function
def mailling(subject,content,sender,password,receiver,mailserver):
    try:
        sender_format = email.utils.formataddr(('运维部', sender))
        msg = email.mime.multipart.MIMEMultipart()
        msg['from'] = sender_format
        msg['to'] = receiver
        msg['subject'] = subject
        txt=email.mime.text.MIMEText(content)
        msg.attach(txt)
        mail = smtplib.SMTP()
        mail.connect(mailserver,'25')
        mail.login(sender,password)
        mail.sendmail(sender_format,receiver,str(msg))
        mail.quit()
    except smtplib.SMTPRecipientsRefused as e:
        print(e)

# notify: Dict unusual_user: {name: [[ok_ip,counts],[[nook_ip,counts],...]],...}
contents = 'From  {}  To  {} , 共 {} 人疑有异常登录:\n'.format(seven_days_ago, datetime.date.today(),len(unusual_user))
for user,info in unusual_user.items():
    message1 = '\n\t常登录:\n\t\t{}({})  成功登陆{}次\n\t疑似异常登录:'.format(info[0][0], info[0][2], info[0][1])
    content = '{}:\n\n\t根据您在 {} ~ {} 期间的登录信息 , 判断您的邮箱密码极有可能已经被盗 ! 建议及时修改密码 !\n'.format\
        (user.upper(),seven_days_ago, datetime.date.today())
    content += message1
    contents += '\n{}:'.format(user.upper())
    contents += message1
    for line in info[1]:
        message2 = "\n\t\t{}({})  成功登录{}次".format(line[0], line[2], line[1])
        content += message2
        contents += message2
    content += '\n\n\n 请勿回复此邮件。如有疑问，请发邮件到tech_group@staff.hexun.com ，并附上此邮件;  或致电 010-6588 0142 。'
    content += '\n\n-----------------------------'
    content += '\n 和讯网  系统运维部'
    contents += '\n'

    receiver = '{}@staff.hexun.com'.format(user)
    #receiver = 'xujianhua@staff.hexun.com'
    mailling('邮件异常登录提醒',
             content,
             MAILINFO['from'],
             MAILINFO['passwd'],
             receiver,
             MAILINFO['smtpSer']
             )
    time.sleep(1)

# mail all infomation to Admin
mailling('邮件异常登录汇总',
         contents,
         MAILINFO['from'],
         MAILINFO['passwd'],
         MAILINFO['to'],
         MAILINFO['smtpSer'])

