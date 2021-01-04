![Docker Image Version (latest by date)](https://img.shields.io/docker/v/dbsentry/keyper)
![Docker Image Size (latest by date)](https://img.shields.io/docker/image-size/dbsentry/keyper)
![GitHub issues](https://img.shields.io/github/issues/dbsentry/keyper)
![GitHub last commit](https://img.shields.io/github/last-commit/dbsentry/keyper)
![GitHub](https://img.shields.io/github/license/dbsentry/keyper)
![CodeQL](https://github.com/dbsentry/keyper/workflows/CodeQL/badge.svg)  
![Keyper Architecture](https://keyper.dbsentry.com/media/keyper.png)  

Keyper is an SSH Key Based Authentication Manager. It standardizes and centralizes the storage of SSH public keys for all Linux users in your organization saving significant time and effort it takes to manage SSH public keys on each Linux Server. Keyper is a lightweight container taking less than 100MB. It is launched either using Docker or Podman. You can be up and running within minutes instead of days.

Features include:
- Public key storage
- Public Key Expiration
- Forced Key rotation
- Streamlined provision or de-provisioning of users
- Segmentation of Servers using groups
- Policy definition to restrict user's access to server(s)
- Centralized user account lockout
- Docker container

## Installation/Build
If you are looking to build docker image for Keyper SSH Key based authentication manager head over to [keyper-docker](https://github.com/dbsentry/keyper-docker) project.
Follow the steps if you intend to run keyper as standalone REST API:
1. Clone this git repository
```console
$ git clone https://github.com/dbsentry/keyper.git
```
2. Initialize python environment
```console
$ cd keyper
$ rm -rf env/*
$ python3 -m venv env
$ . env/bin/activate
$ pip install -r requirements.txt
```
3. Modify ```config.py``` and adjust variables per your environment
4. Modify ```ldapDefn.py``` to map correct attributes per the directory server you are planning to use. If you are using openldap, you should be able to use this file as is. 
5. Start using ```gunicorn```
```console
$ gunicorn -w 4 "app:create_app()" --bind 0.0.0.0:8000
```
Refer to the [administration guide](https://keyper.dbsentry.com/docs/) for further information.

## Related Projects
- [Keyper-docker](https://github.com/dbsentry/keyper-docker)
- [Keyper-fe](https://github.com/dbsentry/keyper-fe)
- [Keyper-docs](https://github.com/dbsentry/keyper-docs)

## License
All assets and code are under the GNU GPL LICENSE and in the public domain unless specified otherwise.

Some files were sourced from other open source projects and are under their terms and license.
