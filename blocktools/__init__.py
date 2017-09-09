from blocktools.types import *
from hashlib import sha256
import binascii


class BlockHeader:

	def __init__(self, blockchain):
		self.version = uint4(blockchain)
		self.previousHash = hash32(blockchain)
		self.merkleHash = hash32(blockchain)
		self.time = uint4(blockchain)
		self.bits = uint4(blockchain)
		self.nonce = uint4(blockchain)

	def __str__(self):
		return """Version:\t %d
Previous Hash\t %s
Merkle Root\t %s
Time\t\t %s
Difficulty\t %8x
Nonce\t\t %s""" % (
			self.version, hashStr(self.previousHash), hashStr(self.merkleHash),
			str(self.time), self.bits, self.nonce
		)

	def hash(self):
		header_bin = pack_uint4(self.version) + \
			pack_hash32(self.previousHash) + \
			pack_hash32(self.merkleHash) + \
			pack_uint4(self.time) + \
			pack_uint4(self.bits) + \
			pack_uint4(self.nonce)

		return binascii.hexlify(sha256(sha256(header_bin).digest()).digest()[::-1])


class Block:

	def __init__(self, blockchain):
		self.continueParsing = True
		self.magicNum = 0
		self.blocksize = 0
		self.blockheader = ''
		self.txCount = 0
		self.Txs = []

		if self.hasLength(blockchain, 8):
			self.magicNum = uint4(blockchain)
			self.blocksize = uint4(blockchain)
		else:
			self.continueParsing = False
			return

		if self.hasLength(blockchain, self.blocksize):
			self.setHeader(blockchain)
			self.txCount = varint(blockchain)
			self.Txs = []

			for i in range(0, self.txCount):
				tx = Tx(blockchain)
				self.Txs.append(tx)
		else:
			self.continueParsing = False

	def continueParsing(self):
		return self.continueParsing

	def getBlocksize(self):
		return self.blockdize

	def hasLength(self, blockchain, size):
		curPos = blockchain.tell()
		blockchain.seek(0, 2)

		fileSize = blockchain.tell()
		blockchain.seek(curPos)

		tempBlockSize = fileSize - curPos
		# print(tempBlockSize)
		if tempBlockSize < size:
			return False
		return True

	def setHeader(self, blockchain):
		self.blockHeader = BlockHeader(blockchain)

	def __str__(self):
		return """Magic No: \t%8x
Blocksize: \t%d
########## Block Header ##########
%s
##### Tx Count: %d
%s
"""         % (
			self.magicNum, self.blocksize, str(self.blockHeader), self.txCount,
			'\n'.join([str(tx) for tx in self.Txs])
		)


class Tx:

	def __init__(self, blockchain):
		self.version = uint4(blockchain)
		self.inCount = varint(blockchain)
		self.inputs = []
		for i in range(0, self.inCount):
			input = txInput(blockchain)
			self.inputs.append(input)
		self.outCount = varint(blockchain)
		self.outputs = []
		if self.outCount > 0:
			for i in range(0, self.outCount):
				output = txOutput(blockchain)
				self.outputs.append(output)
		self.lockTime = uint4(blockchain)

	def __str__(self):
		return """========== New Transaction ==========
Tx Version: \t%d
Inputs: \t%d
%s
Outputs: \t%d
%s
Lock Time: \t%d
"""     % (
			self.version,
			self.inCount, '\n'.join([str(i) for i in self.inputs]),
			self.outCount, '\n'.join([str(o) for o in self.outputs]),
			self.lockTime
		)

	def hash(self):
		header_bin = pack_uint4(self.version)


		header_bin += pack_varint(self.inCount)
		for inp in self.inputs:
			header_bin += pack_hash32(inp.prevhash) + \
				pack_uint4(inp.txOutId) + \
				pack_varint(inp.scriptLen) + \
				inp.scriptSig + \
				pack_uint4(inp.seqNo)

		header_bin += pack_varint(self.outCount)
		for out in self.outputs:
			header_bin += pack_uint8(out.value) + \
				pack_varint(out.scriptLen) + \
				out.pubkey

		header_bin += pack_uint4(self.lockTime)

		return binascii.hexlify(sha256(sha256(header_bin).digest()).digest()[::-1])


class txInput:

	def __init__(self, blockchain):
		self.prevhash = hash32(blockchain)
		self.txOutId = uint4(blockchain)
		self.scriptLen = varint(blockchain)
		self.scriptSig = blockchain.read(self.scriptLen)
		self.seqNo = uint4(blockchain)

	def __str__(self):
		return """< Previous Hash: \t%s
< Tx Out Index: \t%8x
< Script Length: \t%d
< Script Sig: \t\t%s
< Sequence: \t\t%8x
"""     % (
			hashStr(self.prevhash),
			self.txOutId,
			self.scriptLen,
			hashStr(self.scriptSig),
			self.seqNo
		)


class txOutput:

	def __init__(self, blockchain):
		self.value = uint8(blockchain)
		self.scriptLen = varint(blockchain)
		self.pubkey = blockchain.read(self.scriptLen)

	def __str__(self):
		return """> Value: \t%d
> Script Len: \t%d
> Pubkey: \t%s
"""     % (
			self.value,
			self.scriptLen,
			hashStr(self.pubkey)
		)
