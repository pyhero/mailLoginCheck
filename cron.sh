DIR=$(cd `dirname $0`;echo $PWD)
pyversion=/root/.pyenv/versions/3.5.2/bin/python
if [ ! -x $pyversion ];then
	echo "need python 3.5"
	exit 2
fi
cat > /etc/cron.d/mailnotify << EOF
# check mail login unusual information.
0 6 * * 2 root $pyversion $DIR/chkLogin.py &> /tmp/mail.log
EOF
