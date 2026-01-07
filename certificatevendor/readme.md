potentially rename zymkey certificate vendor

1.) Logging
2.) distributed tracing

next
certprovider here?
hackershelter.internal

# setting up the raspberry pi
mv certificatevendor.service to /etc/systemd/services/
sudo useradd certificatevendor
sudo mkdir /home/certificatevendor
sudo chown certificatevendor:certificatevendor /home/certificatevendor
sudo systemctl daemon-reload
sudo systemctl start certificatevendor.service