# Copyright [2020] [cert-exporter authors]

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

certFolder=$1
days=$2

pushd $certFolder

# keys
openssl genrsa -out root.key
openssl genrsa -out client.key
openssl genrsa -out server.key
openssl genrsa -out bundle_root.key
openssl genrsa -out bundle_server.key

# root cert & bundle root cert
openssl req -x509 -new -nodes -key root.key -subj "/C=US/ST=KY/O=Org/CN=root" -sha256 -days $days -out root.crt
openssl req -x509 -new -nodes -key bundle_root.key -subj "/C=BE/ST=EF/O=Org/CN=bundle-root" -sha256 -days $days -out bundle_root.cert

# csrs
openssl req -new -sha256 -key client.key -subj "/C=US/ST=KY/O=Org/CN=client" -out client.csr
openssl req -new -sha256 -key server.key -subj "/C=US/ST=KY/O=Org/CN=example.com" -out server.csr
openssl req -new -sha256 -key bundle_server.key -subj "/C=BE/ST=EF/O=Org/CN=example-bundle.be" -out bundle_server.csr

openssl x509 -req -in client.csr -CA root.crt -CAkey root.key -CAcreateserial -out client.crt -days $days -sha256
openssl x509 -req -in server.csr -CA root.crt -CAkey root.key -CAcreateserial -out server.crt -days $days -sha256
openssl x509 -req -in bundle_server.csr -CA bundle_root.cert -CAkey bundle_root.key -CAcreateserial -out bundle_server.cert -days $days -sha256


# create bundle
cat bundle_server.cert bundle_root.cert > bundle.crt

popd