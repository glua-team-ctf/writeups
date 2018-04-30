# smarter (sl0thcoin, 420 pts)
This year's Blaze CTF featured an entire section dedicated to Ethereum ("`sl0thcoin`"). One of the challenges, `smarter`, required you to reverse engineer an Ethereum smart contract to recover the flag.

```js
Smart contracts are getting smarter all the time.

Update:

abi = [
    {"constant":true,"inputs":[],"name":"isSolved","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},
    {"constant":false,"inputs":[{"name":"input","type":"bytes"}],"name":"checkFlag","outputs":[],"payable":true,"stateMutability":"payable","type":"function"},
    {"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"}
]

Author : itsZN

Files: smarter.bin
```

Various tools for analyzing unknown smart contracts already exist, such as:
* Porosity, a decompiler (https://github.com/comaeio/porosity)
* Ethersplay, a disassembler (https://github.com/trailofbits/ethersplay)

[Porosity's output](./smarter.porosity.dec) leaves a lot to be desired and we had zero interest in wading through disassembly. Luckily, we had previously written a Solidity decompiler that produces more helpful, albeit verbose output, available here:
* https://ethervm.io/decompile

Throwing the constructor bytecode through our decompiler, we get:
```js
contract Contract {
    function main() {
        memory[0x40:0x60] = 0x60;
        var temp0 = 0x0100 ** 0x00;
        storage[0x00] = !!0x00 * temp0 | (~(0xff * temp0) & storage[0x00]);
    
        if (msg.value) { revert(memory[0x00:0x00]); }
    
        memory[0x00:0x1df5] = code[0x38:0x1e2d];
        return memory[0x00:0x1df5];
    }
}
```
This tells us that the contract has one member variable, the constructor is non-`payable` and the runtime bytecode starts at position `0x38` onwards. By doing simple surgery on the bytecode, we can extract the runtime bytecode (starting at the 2nd instance of `6060`) and submit it for decompilation.

We've uploaded the contract to the Ropsten testnet and made the decompiler output available at https://ethervm.io/decompile?address=0x8baae1b64dccfee7b88244b41b9c0c4f587e7345&network=ropsten

The decompiler identifies 8 methods defined in the contract's dispatch table and 7 internal functions:
```
0x5b61291c Unknown
0x64d98f6e isSolved()
0x6c54fcef Unknown
0x7430306c Unknown
0xb220f73c Unknown
0xb4eff690 checkFlag(bytes)
0xd6385778 Unknown
0xf605fa57 Unknown
```
```
func_029F() returns (r0)
func_02B5(arg0)
func_073D(arg0)
func_0BCC(arg0)
func_1195(arg0)
func_1869(arg0)
func_1DBD()
```

The flag is the input to `checkFlag` that makes `isSolved` return `true`.

## checkFlag(bytes) / func_0BCC(bytes)
[Decompilation](https://ethervm.io/decompile?address=0x8baae1b64dccfee7b88244b41b9c0c4f587e7345&network=ropsten#func_0BCC)

We can see that the body for `checkFlag(bytes)` calls `func_0BCC`. `func_0BCC` starts with a repeating pattern:
```js
    function func_0BCC() {
        var var0 = 0x6600000000000000000000000000000000000000000000000000000000000000;
        var var1 = arg0;
        var var2 = 0x00;
    
        if (var2 >= memory[var1:var1 + 0x20]) { assert(); }
    
        if (~0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff & 0x0100000000000000000000000000000000000000000000000000000000000000 * (memory[0x20 + var1 + var2:0x20 + var1 + var2 + 0x20] / 0x0100000000000000000000000000000000000000000000000000000000000000) != var0) { goto label_0038; }
        
        var0 = 0x0c7c;
        // Method call to func_1DBD
        var0 = 0x6c00000000000000000000000000000000000000000000000000000000000000;
        var1 = arg0;
        var2 = 0x01;
    
        if (var2 >= memory[var1:var1 + 0x20]) { assert(); }
    
        if (~0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff & 0x0100000000000000000000000000000000000000000000000000000000000000 * (memory[0x20 + var1 + var2:0x20 + var1 + var2 + 0x20] / 0x0100000000000000000000000000000000000000000000000000000000000000) != var0) { goto label_0038; }
    
        ...
```
Here we see the two anti-reversing techniques used. The gotos to `label_0038` jump to the `0x5b` (`JUMPDEST`) in the `0x5b61291c` of the dispatch table. This unlikely `JUMP` is used to complicate the control flow graph and is used instead of the standard `0xFE` or `REVERT` opcodes used to abort execution. This has the effect of introducing copies of the dispatch table throughout our decompilation, which are easy to spot and remove by hand.

We also see method calls to `func_1DBD`. The [decompilation](https://ethervm.io/decompile?address=0x8baae1b64dccfee7b88244b41b9c0c4f587e7345&network=ropsten#func_1DBD) for it suggests it is a no-op:
```js
    function func_1DBD() {
        var var0 = 0x1dc6 + 0x00;
        // Could not resolve jump destination (is this a return?)
    }
```
This seems fishy, so we check the [disassembly](https://ethervm.io/decompile?address=0x8baae1b64dccfee7b88244b41b9c0c4f587e7345&network=ropsten#1DBD) to confirm:
```js
label_1DBD:
	// Incoming call from 0x0FDB, returns to 0x0FDC
	// Incoming call from 0x189B, returns to 0x189C
	...
	1DBD    5B  JUMPDEST
	1DBE    60  PUSH1 0x00
	1DC0    61  PUSH2 0x1dc6
	1DC3    01  ADD
	1DC4    80  DUP1
	1DC5    56  *JUMP
	// Stack delta = +1
	// Outputs [1] { @1DC3  stack[0] = 0x1dc6 + 0x00 }
	// Block ends with unconditional jump to 0x1dc6 + 0x00

label_1DC6:
	// Incoming jump from 0x1DC5
	// Inputs [1] { @1DC8  stack[-2] }
	1DC6    5B  JUMPDEST
	1DC7    50  POP
	1DC8    56  *JUMP
	// Stack delta = -2
	// Block ends with unconditional jump to stack[-2]
```
We see that `func_1DBD` consists of two blocks and really does nothing, but has a `JUMP` to `0x1DC6 + 0x00` in it to throw off weaker analyzers.

The pattern of asserts in `checkFlag(bytes)` tells us that the flag is 32 bytes long, starts with `flag{` and ends with `s}`. The next part of `func_0BCC` is a little confusing, since the decompiler handles loops poorly, but it can be seen that the contract calls method `0xf605fa57` on itself with the submitted flag.

## 0xf605fa57(bytes) / func_1869(bytes)
[Decompilation](https://ethervm.io/decompile?address=0x8baae1b64dccfee7b88244b41b9c0c4f587e7345&network=ropsten#func_1869)

A quick look at the decompiled dispatch table shows that `0xf605fa57(bytes)` is implemented in `func_1869`.
`func_1869` takes the bytes at `0x1a`, `0x1b`, `0x1c` and `0x1d` and `keccak256`s them. 
This is later compared against something like `keccak256(address(msg.sender).code[0x59:0x5d])`. `msg.sender` is the contract itself at this point and bytes `0x59` to `0x5d` of the bytecode are `74 30 30 6c` or `t00l`.

We now have `flag{?????????????????????t00ls}` for the flag.

`func_1869` also calls `0xd6385778` with the flag after xoring each byte with `msg.value`. `msg.value` can be inferred to be `0x2a` from the start of `func_1869`:
```js
        if (msg.value != 0x2a) { selfdestruct(0x00); }
        ...
        if (tx.gasprice != 0x066a44) { goto label_0038; }
```

## 0xd6385778(bytes) / func_1195(bytes)
[Decompilation](https://ethervm.io/decompile?address=0x8baae1b64dccfee7b88244b41b9c0c4f587e7345&network=ropsten#func_1195)

`0xd6385778(bytes)` is implemented in `func_1195(bytes)`.

`func_1195` takes the bytes from `0x05` to `0x0c` and `keccak256`s them. The result is compared against something like `keccak256(0x74f794a249c48cbd04/block.number)`. `block.number` is `0x01a4`:
```js
        if (block.number != 0x01a4) { goto label_0038; }
```
This gives us another part of the flag:
```python
>>> hex(0x74f794a249c48cbd04 // 0x01a4 ^ 0x2a2a2a2a2a2a2a2a)
'0x6d617962335f7733'
```
We now have `flag{mayb3_w3?????????????t00ls}`.

`func_1195` also calls `0xb220f73c` with the xored flag.

## 0xb220f73c(bytes) / func_073D(bytes)
[Decompilation](https://ethervm.io/decompile?address=0x8baae1b64dccfee7b88244b41b9c0c4f587e7345&network=ropsten#func_073D)

`0xb220f73c(bytes)` is implemented in `func_073D(bytes)`.

At the top of this function is an assert that tells us that byte `0x0d` of the flag is `0x75 ^ 0x2a` or `_`.

We now have `flag{mayb3_w3_????????????t00ls}`.

Bytes `0x0e`, `0x0f`, `0x10` and `0x11` of the xored flag are loaded into memory and passed to a call to `address(0x02)`. This is a special address that performs SHA-256 hashes. The resulting hash + 1 is supposed to be equal to `0xa8c8af687609bf404c202ac1378e10cd19421e72c0a161edc56b53752326592b`.

**Spoiler:** It's `sha256("D\x19\x19N")`

A call is made to `0x6c54fcef` with the xored flag.

## 0x6c54fcef(bytes) / func_02B5(bytes)
[Decompilation](https://ethervm.io/decompile?address=0x8baae1b64dccfee7b88244b41b9c0c4f587e7345&network=ropsten#func_02B5)

`0x6c54fcef(bytes)` is implemented in `func_02B5(bytes)`.

`func_02B5` builds a value from bytes `0x12` to `0x19` of the flag (`temp0` here), does some math and asserts that the result is `0x02f0c798885c9f2975b114`.
```js
        var0 = (temp0 + temp0 * msg.gas * msg.value) * tx.gasprice;
        if (0x02f0c798885c9f2975b114 == var0) {
            // Could not resolve jump destination (is this a return?)
        } else { goto label_0038; }
```
From looking back at `func_073D`, `msg.value` is `0` and from `func_1869`, `tx.gasprice` is `0x066a44`.
We can recover more of the flag with simple arithmetic:
```python
>>> hex(0x02f0c798885c9f2975b114 // 0x066a44 ^ 0x2a2a2a2a2a2a2a2a)
'0x5f7265747433625f'
```
We now have `flag{mayb3_w3_????_b3tter_t00ls}`.

Some guesswork gives us the final flag: `flag{mayb3_w3_n33d_b3tter_t00ls}`.
