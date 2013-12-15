echo "Downloading Berkeley DB source..."
wget --no-cache http://208.111.133.54/berkeley-db/db-4.7.25.tar.gz

echo "Downloading OpenLDAP source..."
wget --no-cache ftp://ftp.openldap.org/pub/OpenLDAP/openldap-stable/openldap-stable-20090411.tgz

echo "Extracting source downloads..."
tar xzvf openldap-stable-20090411.tgz
tar xzvf db-4.7.25.tar.gz

echo "Building autoPosixIds dependancies (OpenLDAP libs which requires Berkeley DB to successfully configure)"

echo "Configuring Berkeley DB..."
cd db-4.7.25/build_unix
../dist/configure
make install

CPPFLAGS="-I/usr/local/BerkeleyDB.4.7/include"
export CPPFLAGS
LDFLAGS="-L/usr/local/lib -L/usr/local/BerkeleyDB.4.7/lib -R/usr/local/BerkeleyDB.4.7/lib"
export LDFLAGS
LD_LIBRARY_PATH="/usr/local/BerkeleyDB.4.7/lib"
export LD_LIBRARY_PATH

echo "Configuring OpenLDAP..."
cd ../../openldap-2.4.16
./configure

echo "Building OpenLDAP dependancies..."
make depend

echo "Building and installing autoPosixIds..."
cd ../
make autoPosixIds.so

if [ -d "/var/lib/ldap" ]; then
	echo "Moving autoPosixIds.so to /var/lib/ldap (LDAP module directory)"
        mv autoPosixIds.so /var/lib/ldap
else
        echo "/var/lib/ldap does not exist. Leaving autoPosixIds.so in $(pwd) for manual installation."
fi

echo "Cleaning up source downloads..."

echo "Removing Berkeley DB..."
rm -rf db-4.7.25/
rm db-4.7.25.tar.gz

echo "Removing OpenLDAP..."
rm -rf openldap-2.4.16/
rm openldap-stable-20090411.tgz

echo "Build complete!"
echo "Don't forget to update your slapd.conf with the appropriate moduleload and overlay directives as illustrated in conf/slapd.conf.example."
