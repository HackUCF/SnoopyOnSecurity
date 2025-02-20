if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

dnf install -y mod_security wget

sed -i "s/SecRuleEngine DetectionOnly/SecRuleEngine On/g" /etc/httpd/conf.d/mod_security.conf
sed -i "s/SecAuditLogParts [A-Z]*/SecAuditLogParts ABCEFHJKZ/g" /etc/httpd/conf.d/mod_security.conf
echo "SecAuditLogFormat JSON" >> /etc/httpd/conf.d/mod_security.conf

wget https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.10.0.tar.gz
tar -xvf v4.10.0.tar.gz 
rm v4.10.0.tar.gz
mv coreruleset-4.10.0 /etc/httpd/modsecurity-crs
cp /etc/httpd/modsecurity-crs/crs-setup.conf.example /etc/httpd/modsecurity-crs/crs-setup.conf

semanage fcontext -a -t httpd_config_t "/etc/httpd/modsecurity-crs(/.*)?"
restorecon -Rv /etc/httpd/modsecurity-crs

sed -i "/<\/IfModule>/d" /etc/httpd/conf.d/mod_security.conf
echo '''
    Include    /etc/httpd/modsecurity-crs/crs-setup.conf
    Include    /etc/httpd/modsecurity-crs/rules/*.conf
</IfModule>
''' >> /etc/httpd/conf.d/mod_security.conf

rm /etc/httpd/modsecurity-crs/rules/REQUEST-922-MULTIPART-ATTACK.conf

systemctl restart httpd
