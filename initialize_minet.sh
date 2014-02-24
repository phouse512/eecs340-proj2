make clean
make

cd bin
rm device_driver2
rm reader
rm writer

ln -s /usr/local/eecs340/device_driver2
ln -s /usr/local/eecs340/reader
ln -s /usr/local/eecs340/writer

cd ..
cd fifos

chmod a+w ether2mon
chmod a+w ether2mux

cd ..
