proxyquire = require('proxyquireify')(require)

OriginalWalletCrypto = require('../src/wallet-crypto');
# BitcoinJS = require('bitcoinjs-lib');

# mock derivation to generate hdnode from string deterministically
MyWallet =
  wallet:
    syncWallet: () ->
    hdwallet:
      getMasterHDNode: () ->
        deriveHardened: (purpose) ->
          deriveHardened: (payloadType) ->
            deriveHardened: (i) -> BitcoinJS.HDNode.fromSeedBuffer(
                                     OriginalWalletCrypto.sha256(
                                      "m/#{ purpose }'/#{ payloadType }'/#{ i }'"))

BitcoinJS = {
}
# disable encryption layer
WalletCrypto = {
  encryptDataWithKey: (data, key) -> Buffer.from(data).toString('base64'),
  decryptDataWithKey: (data, key) -> Buffer.from(data, 'base64').toString()
}
stubs = {
  './wallet-crypto': WalletCrypto,
  'bitcoinjs-lib': BitcoinJS,
  './wallet': MyWallet
}

Metadata = proxyquire('../src/metadata', stubs)

describe "Metadata", ->

  c = undefined
  helloWorld = {hello: "world"}
  unencryptedData = JSON.stringify(helloWorld)
  encryptedData = "eyJoZWxsbyI6IndvcmxkIn0="
  serverPayload = {
    version:1,
    type_id:2
    payload: encryptedData,
    signature:"HysANE1TFkCEX/5zxj+8BXKtld4FIjVXqOKl3K1XdMj8HT5RsigY3iF4LOvMT5IpstZZYAcchZTB4xZrJZPkdKM=",
    created_at:1468316898000,
    updated_at:1468316941000,
  }
  expectedPayloadPUT = {
    version:1,
    type_id:2
    payload: encryptedData,
    signature:"HysANE1TFkCEX/5zxj+8BXKtld4FIjVXqOKl3K1XdMj8HT5RsigY3iF4LOvMT5IpstZZYAcchZTB4xZrJZPkdKM="
  }

  describe "class", ->
    describe "new Metadata()", ->

      it "should instantiate", ->
        c = new Metadata(2)
        expect(c.constructor.name).toEqual("Metadata")

      it "should set the address", ->
        expect(c._address).toEqual("13A5G6RfnG5dEtQvw6Yq8t8CH7bU5wKpTR")

      it "should set the signature KeyPair", ->
        expect(c._signatureKeyPair.toWIF()).toEqual("KzqabBBuqVMacWmiuw21zccSTuXuLQYoMDj1ZVN8GS5ceT7mGDoj")

      it "should set the encryption key", ->
        expect(c._encryptionKey.toString('hex')).toEqual("7ff633262c6adadba38f55ab871a2c7ec2720b4cfed225fe9e25c9fd057c9b95")


  describe "API", ->
    beforeEach ->
      c = new Metadata(2)
      spyOn(c, "request").and.callFake((method, endpoint, data) ->
        if method == "GET" && endpoint == "13A5G6RfnG5dEtQvw6Yq8t8CH7bU5wKpTR"
          Promise.resolve(serverPayload)
        else # 404 is resolved as null
          Promise.resolve(null)
      )

    describe "API", ->
      describe "GET", ->
        it "should call request with GET", ->
          c.GET("13A5G6RfnG5dEtQvw6Yq8t8CH7bU5wKpTR")
          expect(c.request).toHaveBeenCalledWith(
            'GET',
            "13A5G6RfnG5dEtQvw6Yq8t8CH7bU5wKpTR",
            undefined
          )

        it "should resolve with an encrypted payload",  ->
          promise = c.GET("13A5G6RfnG5dEtQvw6Yq8t8CH7bU5wKpTR")
          expect(promise).toBeResolvedWith(serverPayload)

        it "should resolve 404 with null",  ->
          promise = c.GET("non existing address")
          expect(promise).toBeResolvedWith(null)

      describe "PUT", ->
        it "should call request with PUT", ->
          c.PUT("13A5G6RfnG5dEtQvw6Yq8t8CH7bU5wKpTR", "new_payload")
          expect(c.request).toHaveBeenCalledWith(
            'PUT',
            "13A5G6RfnG5dEtQvw6Yq8t8CH7bU5wKpTR",
            "new_payload"
          )

  describe "instance", ->
    promise = undefined

    beforeEach ->
      c = new Metadata(2)

      spyOn(c, "GET").and.callFake((endpoint, data) ->
        switch endpoint
          when "13A5G6RfnG5dEtQvw6Yq8t8CH7bU5wKpTR" then Promise.resolve(serverPayload)
          when "wrong-address" then Promise.resolve(null)
          else Promise.reject("Unknown endpoint")
      )
      spyOn(c, "PUT").and.callFake((endpoint, data) ->
        dec = WalletCrypto.decryptDataWithKey(data.payload, 'mykey')
        switch dec
          when '"fail"' then Promise.reject()
          else Promise.resolve({})
      )

    describe "create", ->
      it "should encrypt data", (done) ->
        spyOn(WalletCrypto, "encryptDataWithKey").and.callThrough()
        c.create({hello: 'world'}).then ->
          expect(WalletCrypto.encryptDataWithKey).toHaveBeenCalledWith(
            JSON.stringify({hello: 'world'}),
            c._encryptionKey
          )
          done()

      it "magicHash should be null initially", ->
        expect(c._magicHash).toEqual(null)

      it "value should be null initially", ->
        expect(c._value).toEqual(null)

      describe "PUT", ->
        putData = undefined
        beforeEach (done) ->
          # spyOn(WalletCrypto, "encryptDataWithKey").and.callFake((endpoint, data) -> "GOxW6Sdo5snuttk62tqvjexwg5NZjBTb5rT+uIRNcop14IwuPLy0c/poILGDswUs")
          spyOn(WalletCrypto, "encryptDataWithKey").and.callThrough()
          c.create({hello: 'world'}).then ->
            putData = c.PUT.calls.argsFor(0)[1]
            done()

        it "should be called", ->
          expect(c.PUT).toHaveBeenCalled()

        it "should use the right address", ->
          expect(c.PUT.calls.argsFor(0)[0]).toEqual("13A5G6RfnG5dEtQvw6Yq8t8CH7bU5wKpTR")

        it "should use version 1", ->
          expect(putData.version).toEqual(1)

        it "should use the right payload type", ->
          expect(putData.type_id).toEqual(c._payloadTypeId)

        it "should send encrypted payload", ->
          expect(putData.payload).toEqual(expectedPayloadPUT.payload)

        it "should send signature", ->
          expect(putData.signature).toEqual(expectedPayloadPUT.signature)

        it "should not send additional arguments", ->
          expect(Object.keys(putData).length).toEqual(5)

      describe "if successful", ->
        beforeEach ->
          promise = c.create({hello: 'world'})

        it "should resolve", (done) ->
          expect(promise).toBeResolved(done)

        it "should remember the new value", (done) ->
          promise.then(() ->
            expect(c._value).toEqual({hello: "world"})
            done()
          )

      describe "if failed", ->
        beforeEach ->
          promise = c.create('fail')

        it "should reject", (done) ->
          expect(promise).toBeRejected(done)

        it "should not have a value or magic hash", (done) ->
          promise.catch(() ->
            expect(c._magicHash).toEqual(null)
            done()
          )

    describe "fetch", ->
      it "magicHash should be null initially", ->
        expect(c._magicHash).toEqual(null)

      it "value should be null initially", ->
        expect(c._value).toEqual(null)

      it "should GET", (done) ->
        c.fetch().then( ->
          expect(c.GET).toHaveBeenCalled()
          done()
        ).catch(done)

      it "should use the right address", (done) ->
        c.fetch().then( ->
          expect(c.GET.calls.argsFor(0)[0]).toEqual("13A5G6RfnG5dEtQvw6Yq8t8CH7bU5wKpTR")
          done()
          ).catch(done)

      it "should decrypt data and verify signature", (done) ->
        spyOn(WalletCrypto, "decryptDataWithKey").and.callThrough()
        spyOn(BitcoinJS.message, "verify").and.callThrough()

        c.fetch().then(() ->
          expect(WalletCrypto.decryptDataWithKey).toHaveBeenCalledWith(
            encryptedData,
            c._encryptionKey
          )
          expect(BitcoinJS.message.verify).toHaveBeenCalled()
          args = BitcoinJS.message.verify.calls.argsFor(0)
          expect(args[0]).toEqual("13A5G6RfnG5dEtQvw6Yq8t8CH7bU5wKpTR")
          expect(args[1].toString('base64')).toEqual(serverPayload.signature)
          expect(args[2]).toEqual(encryptedData)
          done()
        ).catch(done)



      describe "if successful", ->
        beforeEach ->
          promise = c.fetch()

        it "should resolve with payload", (done) ->
          expect(promise).toBeResolvedWith(jasmine.objectContaining({hello: "world"}), done)

        it "should remember the new value", (done) ->
          promise.then(() ->
            expect(c._value).toEqual({hello: "world"})
            done()
          )

      describe "if resolved with null", ->
        beforeEach ->
            c._payloadTypeId = 3
            c._address = "13A5G6RfnG5dEtQvw6Yq8t8CH7bU5wKpTR"
            promise = c.fetch()

        it "should return null", (done) ->
          expect(promise).toBeResolvedWith(null)
          done()

      describe "if failed", ->
        beforeEach ->
            c._payloadTypeId = -1
            c._address = "fail"
            promise = c.fetch()

        it "should reject", (done) ->
          expect(promise).toBeRejected()
          done()

        it "should not have a value or magic hash", (done) ->
          promise.catch(() ->
            expect(c._magicHash).toEqual(null)
            done()
          )

    describe "update", ->
      beforeEach ->
        c._magicHash = ""
        c._value = helloWorld
        c._previousPayload = '{"hello":"world"}'
        spyOn(WalletCrypto, "encryptDataWithKey").and.callThrough()


      it "should update on the server",  (done) ->
        promise = c.update({hello: 'world again'})
        expect(promise).toBeResolved()

        promise.then(() ->
          expect(WalletCrypto.encryptDataWithKey).toHaveBeenCalledWith(
            JSON.stringify({hello: 'world again'}),
            c._encryptionKey
          )
          done()
        )

      describe "if successful", ->
        beforeEach ->
          promise = c.update({hello: 'world again'})

        it "should remember the new value", (done) ->
          promise.then(() ->
            expect(c._value).toEqual({hello: "world again"})
            done()
          )

        it "should remember the magic hash", (done) ->
          promise.then(() ->
            expect(c._magicHash.toString('hex')).toEqual("0453a7ac2c9824e20e858f284b9042d76efc150bfdb2b9d99d8e29b042a16857")
            done()
          )

      describe "if failed", ->
        beforeEach ->
            c._payloadTypeId = -1
            c._address = "fail"
            promise = c.update({hello: 'world again'})

        it "should reject", (done) ->
          expect(promise).toBeRejected()
          done()
