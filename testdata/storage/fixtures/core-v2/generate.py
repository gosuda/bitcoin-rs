#!/usr/bin/env python3
"""Reproduce Bitcoin Core v31.1 CreateBlockChain(200), ask Core to dump it.

Reference: bitcoin/bitcoin v31.1 src/test/util/mining.cpp:33-64 and
src/test/fuzz/utxo_snapshot.cpp:42-72. No caller-supplied trust is accepted.
The snapshot is emitted exclusively by the unmodified pinned Core binary.
"""
import argparse, base64, hashlib, json, pathlib, socket, struct, subprocess, time, urllib.request

BASE = '385901ccbd69dff6bbd00065d01fb8a9e464dede7cfe0372443884f9b1dcf6b9'
COMMITMENT = '17dcc016d188d16068907cdeb38b75691a118d43053b8cd6a25969419381d13a'
BINARY_SHA256 = '986e63b3c8770f08d0059820ad3dd085d1ab9e1bea23946c243f858a06888a08'
u32 = lambda n: struct.pack('<I', n)
u64 = lambda n: struct.pack('<Q', n)
def dsha(data): return hashlib.sha256(hashlib.sha256(data).digest()).digest()
def require_equal(actual, expected, description):
    if actual != expected:
        raise RuntimeError(f'{description}: expected {expected!r}, got {actual!r}')

def script_num(n):
    if n <= 16: return bytes([0x50+n])
    raw = n.to_bytes((n.bit_length()+7)//8, 'little')
    if raw[-1]&128: raw += b'\x00'
    return bytes([len(raw)])+raw

def blocks():
    prev = bytes.fromhex('0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206')[::-1]
    script = b'\x00\x20'+hashlib.sha256(b'\x51').digest()
    for height in range(1,201):
        cb_script = script_num(height)+b'\x00'
        value = 5000000000 >> (height//150)
        tx = u32(2)+b'\x01'+bytes(32)+u32(0xffffffff)+bytes([len(cb_script)])+cb_script+u32(0xfffffffe)+b'\x01'+u64(value)+bytes([len(script)])+script+u32(height-1)
        prefix = u32(4)+prev+dsha(tx)+u32(1296688602+height)+u32(0x207fffff)
        nonce = 0
        while int.from_bytes(dsha(prefix+u32(nonce)),'little') > 0x7fffff << (8*(0x20-3)): nonce += 1
        header = prefix+u32(nonce)
        prev = dsha(header)
        yield (header+b'\x01'+tx).hex()
    require_equal(prev[::-1].hex(), BASE, 'generated chain base')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bitcoind', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    binary = args.bitcoind.resolve()
    actual = hashlib.sha256(binary.read_bytes()).hexdigest()
    if actual != BINARY_SHA256: raise RuntimeError('Core 31.1 x86_64 Linux binary digest mismatch: '+actual)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    datadir = output/'datadir'
    datadir.mkdir(exist_ok=False)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0)); port = sock.getsockname()[1]
    auth = base64.b64encode(b'fixture:fixture').decode()
    def rpc(method, params=None):
        request = urllib.request.Request('http://127.0.0.1:'+str(port), data=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params or []}).encode(),headers={'Authorization':'Basic '+auth,'Content-Type':'application/json'})
        with urllib.request.urlopen(request, timeout=15) as response: result=json.load(response)
        if result.get('error'): raise RuntimeError(str(result['error']))
        return result['result']
    command=[str(binary), '-regtest', '-datadir='+str(datadir), '-server', '-listen=0', '-connect=0', '-dnsseed=0', '-fixedseeds=0','-rpcbind=127.0.0.1','-rpcport='+str(port),'-rpcuser=fixture','-rpcpassword=fixture','-fallbackfee=0.0002']
    log=(output/'core.log').open('wb')
    proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
    try:
        for _ in range(300):
            if proc.poll() is not None: raise RuntimeError('Core exited: '+(output/'core.log').read_text())
            try: rpc('getblockcount'); break
            except Exception: time.sleep(.1)
        else: raise RuntimeError('Core startup timeout')
        block_hex = list(blocks())
        for block in block_hex:
            result=rpc('submitblock',[block])
            if result is not None: raise RuntimeError('submitblock rejected: '+str(result))
        require_equal(rpc('getblockcount'), 200, 'Core block count')
        require_equal(rpc('getbestblockhash'), BASE, 'Core chain base')
        stats=rpc('gettxoutsetinfo',['hash_serialized_3'])
        require_equal(stats['hash_serialized_3'], COMMITMENT, 'Core UTXO commitment')
        result=rpc('dumptxoutset',[str(output/'core200.dat'),'latest'])
        require_equal(result['base_hash'], BASE, 'snapshot base')
        require_equal(result['coins_written'], 200, 'snapshot coin count')
        require_equal(result['txoutset_hash'], COMMITMENT, 'snapshot commitment')
        snapshot=output/'core200.dat'
        manifest={'reference':'Bitcoin Core v31.1','binary_sha256':actual,'source':'https://github.com/bitcoin/bitcoin/blob/9be056a8a72b624dae9623b2f7bded92c2a21c91/src/test/util/mining.cpp#L33-L64','snapshot_sha256':hashlib.sha256(snapshot.read_bytes()).hexdigest(),'size_bytes':snapshot.stat().st_size,'dumptxoutset':result,'gettxoutsetinfo':stats}
        (output/'blocks200.json').write_text(json.dumps(block_hex)+'\n')
        manifest['blocks_sha256'] = hashlib.sha256((output/'blocks200.json').read_bytes()).hexdigest()
        (output/'provenance.json').write_text(json.dumps(manifest,indent=2)+'\n')
        print(json.dumps(manifest,indent=2))
    finally:
        try: rpc('stop')
        except Exception: proc.terminate()
        try: proc.wait(timeout=15)
        except subprocess.TimeoutExpired: proc.kill();proc.wait()
        log.close()
if __name__ == '__main__': main()
