import base64
from paramiko import util
from paramiko.message import Message
from paramiko.rsakey import RSAKey
from paramiko.ssh_exception import SSHException

class RSACert (RSAKey):
    """
    Certificate equivalent of RSAKey
    see http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys?rev=1.9&content-type=text/x-cvsweb-markup
    """

    def __init__(self, msg=None, data=None, privkey_filename=None, cert_filename=None, password=None, vals=None, privkey_file_obj=None, cert_file_obj=None):
        self.nonce = None
        self.n = None
        self.e = None
        self.serial = None
        self.type = None
        self.key_id = None
        self.valid_principals = None
        self.valid_after = None
        self.valid_before = None
        self.critical_options = None
        self.extensions = None
        self.reserved = None
        self.signature_key = None
        self.signature = None
        self.d = None
        self.p = None
        self.q = None

        if cert_filename is not None:
            msg = self._load_cert_from_file(cert_filename)
        elif cert_file_obj is not None:
            msg = self._load_cert(cert_file_obj)
        elif cert_filename is None and cert_file_obj is None and data is None:
            raise SSHException('Either a data object or a certificate file must be given')

        if privkey_file_obj is not None:
            self._from_private_key(privkey_file_obj, password)
        elif privkey_filename is not None:
            self._from_private_key_file(privkey_filename, password)

        if (msg is None) and (data is not None):
            msg = Message(data)
        if vals is not None:
            self.nonce, self.n, self.e, self.serial, self.type, self.key_id, self.valid_principals,\
                self.valid_after, self.valid_before, self.critical_options, self.extensions,\
                self.reserved, self.signature_key, self.signature = vals
        else:
            if msg is None:
                raise SSHException('Key object may not be empty')
            if msg.get_text() != 'ssh-rsa-cert-v01@openssh.com':
                raise SSHException('Invalid key')
            self.nonce = msg.get_string()
            self.e = msg.get_mpint()
            self.n = msg.get_mpint()
            self.serial = msg.get_int64()
            self.type = msg.get_int()
            self.key_id = msg.get_string()
            self.valid_principals = msg.get_string()
            self.valid_after = msg.get_int64()
            self.valid_before = msg.get_int64()
            self.critical_options = msg.get_string()
            self.extensions = msg.get_string()
            self.reserved = msg.get_string()
            self.signature_key = msg.get_string()
            self.signature = msg.get_string()

        self.size = util.bit_length(self.n)

    def get_name(self):
        return 'ssh-rsa-cert-v01@openssh.com'

    def asbytes(self):
        m = Message()
        m.add_string('ssh-rsa-cert-v01@openssh.com')
        m.add_string(self.nonce)
        m.add_mpint(self.e)
        m.add_mpint(self.n)
        m.add_int64(self.serial)
        m.add_int(self.type)
        m.add_string(self.key_id)
        m.add_string(self.valid_principals)
        m.add_int64(self.valid_after)
        m.add_int64(self.valid_before)
        m.add_string(self.critical_options)
        m.add_string(self.extensions)
        m.add_string(self.reserved)
        m.add_string(self.signature_key)
        m.add_string(self.signature)
        return m.asbytes()

    def _load_cert_from_file(self, cert_file):
        with open(cert_file, 'r') as f:
            data = self._load_cert(f)
        return data

    def _load_cert(self, cert_file_obj):
        data = cert_file_obj.read().replace('\n', '')
        data = data.split()
        if len(data) > 1:
            data = data[1]
        else:
            data = data[0]
        return Message(base64.b64decode(data))

    @staticmethod
    def generate(bits, progress_func=None):
        raise Exception('Not implemented in RSACert')