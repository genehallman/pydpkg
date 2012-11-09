#!/usr/local/bin/python

__version__ = 0.1

import hashlib
import re
import sys
import os
import subprocess


class Package(dict):
	TYPE = 'package from unknown source'
	FIELD_ORDER = [
		'Package',
		'Version',
		'Architecture',
		'Maintainer',
		'Depends',
		'Filename',
		'Size',
		'MD5sum',
		'SHA1',
		'SHA256',
		'Section',
		'Priority',
		'Description',
	]

	def __str__(self):
		return '\n'.join(["%s: %s" % (field, self[field])
			for field in self.FIELD_ORDER
			if field in self])

	def ident(self):
		return "%s=%s" % (self['Package'], self['Version'])

	def meta(self):
		return {'name': self['Package'], 'version': self['Version'],}

	def _parse(self, string):
		lines = re.split('\n(?=\w)', string)
		for line in lines:
			field_pair = re.match('^(.*?): ([\s\S]*)', line, flags=re.M)
			(field, value) = field_pair.groups()

			if field in self:
				raise Exception('Duplicate field (%s) detected.' % field)
			if field not in self.FIELD_ORDER:
				raise Exception('Unrecognized field (%s), register in FIELD_ORDER.' % field)

			self[field] = value

	def set_root(self, root):
		self.root = root

	def abs_path(self, root=None):
		if root is None and hasattr(self, 'root'):
			root = self.root
		if root is not None:
			 return os.path.abspath(os.path.join(root, self['Filename']))
		return self['Filename']

	def __eq__(self, other):
		if not isinstance(other, Package):
			print 'Not a package.'
			return False

		for (field, other_value) in other.items():
			if not self._field_eq(field, other_value, other):
				return False

		return True

	def _field_eq(self, field, other_value, other):
		if field not in self:
			print ('Field %s found in %s but not found in %s' %
				(field, other.TYPE, self.TYPE))
			return False

		# Calculate a normalized value by a field
		if field == "Description":
			self_norm = _split_and_rstrip(self[field])
			other_norm = _split_and_rstrip(other_value)
		elif field == "Filename" and hasattr(self, 'root'):
			other_norm = other.abs_path(self.root)
			self_norm = self.abs_path(self.root)
		else:
			other_norm = other_value
			self_norm = self[field]

		# If the projections do not match, print and return false
		if other_norm != self_norm:
			print ('Field %s did not match: \n'
				'%s in %s\nbut mine is %s (%s)' % (field,
					other_norm, other.TYPE, self_norm, self.TYPE))
			return False
		return True


def _split_and_rstrip(string):
	return filter(lambda x: x, map(lambda x: x.rstrip(), string.split('\n')))


class DiskPackage(Package):
	TYPE = 'generated from deb package'
	HASHES = {
		'MD5sum': hashlib.md5,
		'SHA1': hashlib.sha1,
		'SHA256': hashlib.sha256,
	}

	def __init__(self, serve_root, path=None, name=None, version=None):
		super(DiskPackage, self).__init__()

		# Keep the relative root for redisplay and verification
		self.root = serve_root

		# Need to generate the path from the name & version
		if path is None:
			if name is None or version is None:
				raise Exception('Need a name & version or path to read a deb.')
			rel = os.path.join(name[0], name, '%s_%s.deb' % (name, version))
			path = os.path.join(serve_root, 'pool', 'main', rel)
		self.path = os.path.abspath(path)

		# Generate the dpkg-deb output
		direct = subprocess.check_output(['dpkg-deb', '-I', self.path])

		# The output has some head lines we have to ditch
		FIRST_FIELD_MATCHER = re.compile('[\w\W]*^ Package:', re.M)
		begin = re.match(FIRST_FIELD_MATCHER, direct).end()
		# The output has leading spaces we need to strip
		trimmed_output = re.sub('^ ', '', direct[begin:], flags=re.M)

		norm_out = "Package: " + trimmed_output
		self._parse(norm_out)

		# Filename should be relative to the serve_root so that when it
		#	is appended to the url base it will produce a proper url
		self['Filename'] = os.path.relpath(self.path, self.root)
		self['Size'] = str(os.path.getsize(self.path))
		self._hashes_calculated = False

	def __getitem__(self, key):
		if key in self.HASHES:
			self._ensure_hashes()
		return super(DiskPackage, self).__getitem__(key)

	def __contains__(self, key):
		if key in self.HASHES and 'Filename' in self:
			return True
		return super(DiskPackage, self).__contains__(key)

	def _ensure_hashes(self):
		if not self._hashes_calculated:
			self.calculate_hashes()

	def calculate_hashes(self):
		for (field, fn) in self.HASHES.items():
			hasher = fn()
			with open(self.path, 'rb') as deb_file:
				hasher.update(deb_file.read())
				self[field] = hasher.hexdigest()
		self._hashes_calculated = True

	def rough_verify(self, other, verbose=False):
		def field_eq_unless_hash(field, value, other):
			if field in self.HASHES:
				if verbose:
					print "Skipping field %s" % field
				return True
			return super(DiskPackage, self)._field_eq(field, value, other)
		self._field_eq = field_eq_unless_hash
		result = (self == other)
		self._field_eq = super(DiskPackage, self)._field_eq
		return result

	def __str__(self):
		self._ensure_hashes()
		return super(DiskPackage, self).__str__()


class ParsedPackage(Package):
	TYPE = 'parsed from Packages file'

	def __init__(self, string=None, io=None):
		super(ParsedPackage, self).__init__()
		self._parse(string)


def _run_find(root, name_mask):
	# TODO(gregp): pythonify
	# -L follows symlinks -- a symlink loop will crash us -- TODO
	output = subprocess.check_output(['find', '-L', root, '-name', name_mask])
	return filter(lambda x: x.strip(), output.split('\n'))


# TODO(gregp): accept piped input when given a --www-root flag?
class PackageList(dict):
	def __init__(self, path=None, sorting=True, **kwargs):
		# Keep whether we're sorting
		self.sorting = sorting

		# Search for and parse the packages file
		self.path = self._norm_path(path, root=os.getcwd())

		# Parse the packages file and store by ident()
		parsed = self._parse()
		for block in parsed:
			package = ParsedPackage(string=block) 
			self[package.ident()] = package

		# Find the pool.main directory
		common_path = os.path.commonprefix(map(lambda x: x['Filename'], self.values()))
		self.local_serve_root = self._get_serve_root(common_path)

		# Store the packages by path
		self.by_path = {}
		for package in self.values():
			package.set_root(self.local_serve_root)
			self.by_path[package.abs_path()] = package

	def _get_serve_root(self, common_path, cur_path=None):
		def _check_dir(dir_path):
			return os.path.isdir(os.path.join(dir_path, common_path))
		cur_path = os.path.dirname(self.path)
		while cur_path is not '/':
			if _check_dir(cur_path):
				return cur_path
			cur_path = os.path.dirname(cur_path)
		raise Exception('no suitable root found')

	def _norm_path(self, given, root=None):
		if given is None and root is None:
			raise Exception('Need a `Packages` file path or search_root')
		if given is None:
			possible_packages = _run_find(root, name_mask='Packages')
			if len(possible_packages) != 1:
				raise Exception('No unique Packages file in tree (%s). '
					'Found %i possibilities.' % (root, len(possible_packages))
					)
			return possible_packages[0]
		return os.path.abspath(given)

	def _deb_paths(self):
		return _run_find(self.local_serve_root, '*.deb')

	def _new_deb_paths(self):
		return [x for x in self._deb_paths() if x not in self.by_path]

	def missing_packages(self):
		return [DiskPackage(serve_root=self.local_serve_root, path=path)
			for path in self._new_deb_paths()]

	def _parse(self):
		package_blocks = []
		current_block = ""
		with open(self.path, 'r') as packages_file:
			# TODO(gregp): regex?
			for line in packages_file:
				# Start a new block when we hit a Package: ... line
				if line.startswith('Package: '):
					package_blocks.append(current_block.strip())
					current_block = line
				else:
					current_block += line
		return filter(lambda x: x.strip(), package_blocks)

	def verify(self, check_hashes=False, **kwargs):
		for given in self.values():
			deb = DiskPackage(self.local_serve_root, **given.meta())
			if check_hashes:
				print "Verifying checksums: %s" % deb.path
				result = (deb == given) # with hashes
			else:
				print "Verifying: %s" % deb.path
				result = deb.rough_verify(given)
			if not result:
				return False
		return True

	def _numeric_order(self, ident):
		nums = re.split('(\d+)', ident)
		return [int(x) if x.isdigit() else x for x in nums]

	def __iter__(self):
		if self.sorting:
			return iter(sorted(self.keys(), key=self._numeric_order))
		return self.iterkeys()

	def values(self):
		return [self[x] for x in self]


def verify(**kwargs):
	listing = PackageList(**kwargs)
	if not listing.verify(**kwargs):
		print 'Verification Failed'

def missing(**kwargs):
	listing = PackageList(**kwargs)
	for pack in listing.missing_packages():
		print pack

def usage():
	print 'USAGE: %s (missing|verify|fullverify) [PACKAGES_FILE]' % sys.argv[0]
	exit(1)

if __name__ == '__main__':
	if sys.version < 2.7:
		raise Exception('Requires python 2.7+')

	kwargs = {}
	if len(sys.argv) < 2:
		usage()
	elif len(sys.argv) == 2:
		kwargs['search_path'] = os.getcwd()
	else:
		kwargs['path'] = sys.argv[2]

	if sys.argv[1] == "missing":
		missing(**kwargs)
	elif sys.argv[1] == "verify":
		verify(**kwargs)
	elif sys.argv[1] == "fullverify":
		kwargs['check_hashes'] = True
		verify(**kwargs)
	else:
		usage()

