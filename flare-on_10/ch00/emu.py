from unicorn import *
from unicorn.x86_const import *
import base64
import zlib


code = zlib.decompress(base64.b64decode("eJwVkLtPWmEchgNIalosxdjooC6OLlWnbj3q2xyS4yVGNA6YOMhkKtG1GwuXnMXJPwPv6HQO4KvoAbH324VqrxQrahU2+Dm8efLle7/nTb4nPjVWUkOlIBHv0vQhg1gJaLpPuDqHPsHajHtSsL5we9iYJTbnia1nRKKH2H40GMaO2wNDjaAszAciqAoLhLFImHeIZBuRaiTSrcTuPYIuYk+47yEyU8TBKHH4lLA6iWwDkXMSR8J8B3F8l3gxTryUvHIQrx8Sb4Rv7xPv2mX7PfFBeh+HiU/TxOd+4ovcf5V3hSbim/RPZPdU8n2E+DFA/JTdX2PE7wniTzNR1Ii/LUTJRpw9IP6J+9xOlP3EhZe4FN+V+P6L71p8N+KqSKpKImtZllIpKDFDqRlm0aG7lhyZblNdjmrOuBK1eWtmr6mE7d5aUglVHz/Pqbr8VCgd9KfqTrG9kg=="))

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(0x100000,  0x1000)
mu.mem_map(0x700000,  0x1000)

mu.mem_write(0x100000, code)
mu.reg_write(UC_X86_REG_RBP, 0x700100)
mu.reg_write(UC_X86_REG_RSP, 0x700100)
mu.emu_start(0x100000, 0x100000 + len(code) - 1)   # skip ret that sends us to unmapped shithole
print(mu.mem_read(0x700000, 0x100).strip(b'\x00'))
