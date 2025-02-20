if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

apt install -y libapache2-mod-security2 apache2

cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sed -i "s/SecRuleEngine DetectionOnly/SecRuleEngine On/g" /etc/modsecurity/modsecurity.conf
sed -i "s/SecAuditLogParts [A-Z]*/SecAuditLogParts ABCEFHJKZ/g" /etc/modsecurity/modsecurity.conf
echo "SecAuditLogFormat JSON" >> /etc/modsecurity/modsecurity.conf

a2enmod security2

wget https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.10.0.tar.gz
tar -xvf v4.10.0.tar.gz 
rm v4.10.0.tar.gz
mv coreruleset-4.10.0 /etc/apache2/modsecurity-crs
cp /etc/apache2/modsecurity-crs/crs-setup.conf.example /etc/apache2/modsecurity-crs/crs-setup.conf

sed -i "/IncludeOptional \/usr\/share\/modsecurity-crs\/\*\.load/d" /etc/apache2/mods-enabled/security2.conf
sed -i "/<\/IfModule>/d" /etc/apache2/mods-enabled/security2.conf
sed -i "/\/etc\/apache2\/modsecurity-crs\/crs-setup\.conf/d" /etc/apache2/mods-enabled/security2.conf
sed -i "/IncludeOptional \/etc\/apache2\/modsecurity-crs\/rules\/\*\.conf/d" /etc/apache2/mods-enabled/security2.conf

echo '''
IncludeOptional /etc/apache2/modsecurity-crs/crs-setup.conf
IncludeOptional /etc/apache2/modsecurity-crs/rules/*.conf
</IfModule>

<IfModule mod_security2.c>
SecRuleRemoveById 920350 942100 931100
</IfModule>
''' >> /etc/apache2/mods-enabled/security2.conf

rm /etc/apache2/modsecurity-crs/rules/REQUEST-922-MULTIPART-ATTACK.conf

systemctl restart apache2
