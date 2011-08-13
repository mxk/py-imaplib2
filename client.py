
#
# Written by Maxim Khitrov (August 2011)
#

import collections
import functools
import imaplib2
import io
import mailbox
import os
import re
import time

__all__ = ['IMAP4Client', 'IMAP4Message']

IMAP4Error = imaplib2.IMAP4Error

walltime = time.clock if os.name == 'nt' else time.time
walltime()

# Regular expression for extracting Message-ID header from uploaded messages
_msg_id_hdr = re.compile(b'^Message-ID:(.+)$', re.IGNORECASE | re.MULTILINE)

def _use_ssl(addr):
	"""Decide if SSL should be used for the given server address."""
	if isinstance(addr, str):
		return addr.endswith(':993')
	return len(addr) == 2 and addr[1] == 993

def _list2dict(kv):
	"""Convert a key-value list returned by FETCH into a dictionary."""
	return dict((k.upper(), v) for k, v in imaplib2.group(kv))

def _unpack(msg, decode=True):
	"""Unpack and decode a FETCHed message dictionary."""
	if 'UID' in msg and 'BODY[]' in msg:
		uid  = msg['UID']
		body = msg['BODY[]']
		if decode:
			idate = msg.get('INTERNALDATE', None)
			flags = msg.get('FLAGS', ())
			return (uid, IMAP4Message(body, uid, idate, flags))
		else:
			return (uid, body)
	return (None, None)

class IMAP4Client(mailbox.Mailbox):

	def __init__(self, addr, timeout=60, ssl_ctx=None, factory=None):
		"""Connect to an IMAP4 server."""
		self.server_info = {}
		self._factory    = factory
		self._last_noop  = 0
		self._in_iter    = False

		if ssl_ctx is None and _use_ssl(addr):
			ssl_ctx = imaplib2.ssl_context()

		self.cn = imaplib2.IMAP4(addr, timeout, ssl_ctx)
		self._reset_mbox()
		if self.cn.state == 'auth':
			self._post_auth()

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		if self.cn.state != 'logout':
			self.cn.logout()

	#
	# Mailbox interface
	#

	def add(self, msg, header_search=True):
		"""Add message to the mailbox and return its UID."""
		# Get message body and attributes
		body = io.BytesIO()
		self._dump_message(msg, body)
		body = body.getbuffer()

		if isinstance(msg, IMAP4Message):
			flags, idate = msg._flags, msg._idate
		else:
			flags = idate = None

		# Append
		self._check_selected()
		cmd = self.cn.append(self.mbox['name'], body, flags, idate)

		try:
			# Determine UID using UIDPLUS extension (if available)
			if cmd.result.dtype == 'APPENDUID':
				return cmd.result[-1]

			# Get UID and Message-ID header of the last message in the mailbox
			msg = {}
			for seq, _, kv in self.cn.fetch('*', 'UID', 'ENVELOPE'):
				msg.update(_list2dict(kv))

			# Get Message-ID of the original message
			orig_id = _msg_id_hdr.search(body)
			if orig_id:
				orig_id = orig_id.group(1).tobyes().strip() or None

			# Try to match Message-ID headers
			if 'UID' in msg and 'ENVELOPE' in msg:
				last_id = msg['ENVELOPE'][-1]
				if isinstance(last_id, str):
					last_id = last_id.encode()
				if orig_id == last_id or not (orig_id or last_id):
					return msg['UID']

			# Try to search for the original Message-ID
			if orig_id and header_search:
				spec = ('HEADER', 'Message-ID', orig_id)
				for resp in self.cn.search(*spec, uid=True)
					if len(resp) > 1:
						return max(resp[1:])

			raise IMAP4Error('failed to get message uid')
		finally:
			self._update_mbox()

	def remove(self, uid):
		"""Remove the keyed message; raise KeyError if it doesn't exist."""
		self._check_selected()
		for seq, _, kv in self.cn.store(uid, '+FLAGS', '\\Deleted', uid=True):
			if _list2dict(kv).get('UID', None) == uid:
				break
		else:
			raise KeyError(uid)
		if 'UIDPLUS' not in self.cn.caps:
			uid = None  # Have to expunge everything without UIDPLUS
		self.cn.expunge(uid).defer()
		self._update_mbox()

	def __setitem__(self, uid, message):
		"""Update message flags."""
		if not isinstance(msg, IMAP4Message) or msg.uid != uid:
			raise ValueError('unsupported operation')
		self._check_selected()
		self.cn.store(uid, 'FLAGS.SILENT', msg._flags, uid=True)
		self._update_mbox()

	def get_message(self, uid):
		"""Return a Message representation or raise a KeyError."""
		self._check_selected()
		msg = {}
		req = ('BODY.PEEK[]', 'INTERNALDATE', 'FLAGS')
		for seq, _, kv in self.cn.fetch(uid, *req, uid=True):
			kv = _list2dict(kv)
			if kv.get('UID', None) == uid:
				msg.update(kv)
		msg = _unpack(msg)[1]
		if msg is None:
			raise KeyError(uid)
		self._update_mbox()
		return msg

	def get_bytes(self, uid):
		"""Return a byte string representation or raise a KeyError."""
		self._check_selected()
		body = None
		for seq, _, kv in self.cn.fetch(uid, 'BODY.PEEK[]', uid=True):
			kv = _list2dict(kv)
			if 'BODY[]' in kv and kv.get('UID', None) == uid:
				body = kv['BODY[]']
				break
		if body is None:
			raise KeyError(uid)
		self._update_mbox()
		return body

	def get_file(self, uid):
        """Return a file-like representation or raise a KeyError."""
        return io.BytesIO(self.get_bytes(uid))

	def keys(self):
		"""Return an iterator over all message UIDs."""
		for seq, msg in self._iter(('UID',)):
			if 'UID' in msg:
				yield msg['UID']

	def values(self, decode=True):
		"""Return an iterator over all message bodies."""
		for uid, msg in self.items(decode):
			yield msg

	def items(self, decode=True):
		"""Return an iterator over (UID, message) tuples."""
		if decode:
			req = ('UID', 'BODY.PEEK[]', 'INTERNALDATE', 'FLAGS')
		else:
			req = ('UID', 'BODY.PEEK[]')
		for seq, msg in self._iter(req, 10):
			uid, msg = _unpack(msg, decode)
			if msg is not None:
				yield (uid, msg)

	iterkeys, itervalues, iteritems = keys, values, items

	def __contains__(self, uid):
		"""Return True if the UID exists, False otherwise."""
		self._check_selected()
		result = False
		for seq, _, kv in self.cn.fetch(int(uid), 'UID', uid=True):
			if _list2dict(kv).get('UID', None) == uid:
				result = True
				break
		self._update_mbox()
		return result

	def __len__(self):
		self._check_selected()
		return self.mbox['exists']

	def clear(self):
		self._check_selected()
		self.cn.store('1:*', '+FLAGS.SILENT', '\\Deleted')

		mbox = self.mbox['name']
		readonly = self.cn.readonly

		# Use CLOSE-SELECT sequence to avoid receiving EXPUNGE responses
		self._reset_mbox()
		self.cn.close()
		self.cn.select(mbox, readonly).defer()
		self._update_mbox(mbox)

	flush = lock = unlock = lambda self: pass

	def close(self, expunge=False):
		"""Close the current mailbox."""
		if self.cn.state == 'selected':
			self._reset_mbox()
			self.cn.close(expunge)

	#
	# End of Mailbox interface
	#

	def starttls(self, ssl_ctx=None, required=True):
		"""Try to enable TLS encryption."""
		if self.encrypted:
			return True
		try:
			self.cn.starttls(ssl_ctx or imaplib2.ssl_context())
			return True
		except Exception:
			if required:
				raise
		return False

	def login(self, username, password, allow_cleartext=False):
		"""Authenticate using a username and password."""
		if self.cn.state != '!auth':
			return
		if 'AUTH=CRAM-MD5' in self.cn.caps:
			try:
				self.cn.login_cram_md5(username, password)
			except imaplib2.NO:
				pass
		if self.cn.state == '!auth':
			self.cn.login(username, password, allow_cleartext)
		self._post_auth()

	def noop(self, seq=None):
		"""Request status updates from the server."""
		self.cn.noop()
		if self.cn.state == 'selected':
			return self._update_mbox(seq)
		return None

	def walk(self, root=None, subscribed=False, depthfirst=True):
		"""Return an iterator over all available or subscribed mailboxes.

		The generator yields (mbox, delim, flags) tuples, where mbox is a list
		of path steps to a mailbox on the server, delim is the hierarchy
		delimiter, and flags is a set of mailbox flags converted to lower case.
		If '\noselect' is in flags, the mailbox is not selectable.

		Calling generator.send(True) causes the current mailbox to be skipped.
		The generator will not yield any of its children.
		"""
		if root:
			root, delim = self._join_hier(root)
			first = ((), delim, root.split(delim))
		else:
			first = ((), '', [])

		ls    = self.cn.lsub if subscribed else self.cn.list
		queue = collections.deque((first,))
		pop   = queue.pop if depthfirst else queue.popleft
		excl  = {'\\noinferiors', '\\hasnochildren'}

		while queue:
			flags, delim, path = pop()
			if not first:
				skip = yield (path, delim, flags)
				if skip:
					yield None  # Return value for send()
					continue
			else:
				first = None
			if delim is None or flags & excl:
				continue

			# Expand path
			children = []
			ref = delim.join(path) + delim
			for _, flags, delim, mbox in ls(ref, '%'):
				flags = set(map(str.lower, flags)) if flags else ()
				mbox  = imaplib2.iutf7_decode(mbox)
				mbox  = mbox if delim is None else mbox.split(delim)[-1]
				children.append((mbox.lower(), mbox, delim, flags))
			if self.cn.state == 'selected':
				self._update_mbox()
			children.sort(reverse=depthfirst)
			for _, mbox, delim, flags in children:
				queue.append((flags, delim, path + [mbox]))

	def select(self, mbox, readonly=False):
		mbox = self._join_hier(mbox)[0]
		self._reset_mbox()
		self.cn.select(mbox, readonly).defer()
		self._update_mbox(mbox)

	@property
	def authenticated(self):
		"""User authentication status."""
		return self.cn.state in ('auth', 'selected')

	@property
	def selected(self):
		"""Mailbox selection status."""
		return self.cn.state == 'selected'

	@property
	def encrypted(self):
		"""Link encryption status."""
		return self.cn._sock.encrypted

	@property
	def compressed(self):
		"""Data compression status."""
		return self.cn._sock.compressed

	def _post_auth(self):
		"""Perform post-authentication tasks."""
		if 'COMPRESS=DEFLATE' in self.cn.caps:
			self.cn.compress()
		if 'ID' in self.cn.caps:
			for resp in self.cn.id():
				self.server_info.update(imaplib2.group(resp[-1]))

	def _check_selected(self, update=None, rate=30.0):
		"""Check connection state and update mailbox status."""
		if self.cn.state != 'selected':
			raise IMAP4Error('mailbox not selected')

		# Issue NOOP at least every <rate> seconds or when update is set to True
		if update is False or self._in_iter:
			return
		if update is True or walltime() - self._last_noop >= rate:
			self.noop()

	def _join_hier(self, steps):
		"""Join a list of hierarchy steps into a full mailbox name."""
		if isinstance(steps, str):
			delim = self._hier_delim(steps)
			return (steps, delim)
		delim = self._hier_delim(steps[0])
		if delim is None:
			return (steps[0], delim)
		return (steps.join(delim), delim)

	@functools.lru_cache()
	def _hier_delim(self, path):
		"""Get the hierarchy delimiter for the specified path."""
		for rsp in self.cn.list(path, ''):
			return rsp[2]
		raise IMAP4Error('failed to get hierarchy delimiter')

	def _reset_mbox(self):
		"""Reset mailbox information."""
		self.mbox = {
			'name':           '',
			'flags':          (),
			'exists':         0,
			'recent':         0,
			'unseen':         0,
			'permanentflags': (),
			'uidnext':        0,
			'uidvalidity':    0
		}

	def _update_mbox(self, seq=None):
		"""Process all responses in the common queue.

		If seq is specified, it is expected to be the sequence number (SN) of
		the next unprocessed message. The return value will be the adjusted SN
		of the same message, taking into account all received EXPUNGE responses.
		If the message itself is expunged, the returned SN will point to the
		next available unprocessed message. None will be returned if all
		messages have been processed.
		"""
		if seq is None:
			# If _iter is active, no one else may perform updates
			if self._in_iter:
				return None
			seq = 1
		mbox = self.mbox
		for rsp in map(self.cn.claim, self.cn.queued):
			dtype = rsp.dtype.lower() if rsp.dtype else None
			if dtype == 'expunge':
				mbox['exists'] -= 1
				if rsp[0] < seq:
					seq -= 1
			elif dtype in mbox:
				if dtype in ('exists', 'recent'):
					mbox[dtype] = rsp[0]
				else:
					mbox[dtype] = rsp[1]
		self._last_noop = walltime()
		return seq if 1 <= seq <= mbox['exists'] else None

	def _iter(self, req, readahead=100):
		"""Generator of message attributes."""
		if self._in_iter:
			raise RuntimeError('a second iteration is not permitted')
		self._check_selected()
		self._in_iter = True
		try:
			seq  = 1
			msgs = collections.defaultdict(dict)
			while seq and seq <= self.mbox['exists']:
				rng = range(seq, seq + readahead)
				cmd = self.cn.fetch(rng, *req, wait=False)
				for seq, _, kv in cmd:
					msgs[seq].update(_list2dict(kv))
				cmd.check('OK', 'NO')
				for seq in sorted(msgs):
					yield (seq, msgs.pop(seq))
				seq = self.noop(rng[-1] + 1)
		finally:
			self._in_iter = False

class IMAP4Message(mailbox.Message):

	def __init__(self, message=None, uid=None, idate=None, flags=()):
		if isinstance(idate, str):
			idate = imaplib2.idate2unix(idate)

		self.uid    = uid
		self._idate = idate
		self._flags = set(flag.lower() for flag in flags)

		super().__init__(message)

	def get_flags(self):
		"""Return a list of flags that are set."""
		return list(self._flags)

	def set_flags(self, flags):
		"""Set the given flags and unset all others."""
		self._flags.clear()
		self._flags.update(flag.lower() for flag in flags)

	def add_flag(self, flag):
		"""Set the given flag without changing others."""
		self._flags.add(flag.lower())

	def remove_flag(self, flag):
		"""Unset the given flag without changing others."""
		self._flags.discard(flag.lower())

	def test_flag(self, flag):
		"""Test if the given flag is set."""
		return flag.lower() in self._flags

	def get_date(self):
		"""Get INTERNALDATE message attribute, in seconds since the epoch."""
		return self._idate

	def _explain_to(self, message):
		"""Copy format-specific state to message."""
		if isinstance(message, mailbox.MaildirMessage):
			flag_map = {
				'\\draft':    'D',
				'\\flagged':  'F',
				'\\answered': 'R',
				'\\seen':     'S',
				'\\deleted':  'T'
			}
			msg.set_flags(v for k, v in flag_map.items() if k in self._flags)
			if '\\recent' not in self._flags:
				msg.set_subdir('cur')
			if self._idate is not None:
				msg.set_date(self._idate)
		else:
			# Use maildir conversion for all other formats
			maildir = mailbox.MaildirMessage(self)
			maildir._explain_to(message)
