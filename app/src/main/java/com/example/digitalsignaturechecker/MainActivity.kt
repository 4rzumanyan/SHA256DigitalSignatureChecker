package com.example.digitalsignaturechecker

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import org.spongycastle.util.io.pem.PemReader
import java.io.InputStream
import java.io.InputStreamReader
import java.security.KeyFactory
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val result = findViewById<TextView>(R.id.tv)
        if (verifySignature(
                reader = getPublicKeyReader(),
                data = getData(),
                signData = getSignature()
            )
        )
            result.text = getString(R.string.verification_is_ok)
        else
            result.text = getString(R.string.verification_is_fail)
    }

    private fun verifySignature(
        reader: PemReader,
        data: InputStream,
        signData: InputStream
    ): Boolean {
        val publicKeyPem = reader.readPemObject()
        val publicKeyBytes = publicKeyPem.content
        val keyFactory = KeyFactory.getInstance("RSA")
        val publicKeySpec = X509EncodedKeySpec(publicKeyBytes)
        val publicKey = keyFactory.generatePublic(publicKeySpec) as RSAPublicKey

        val signature = Signature.getInstance("SHA256withRSA")
        signature.initVerify(publicKey)

        val buffy = ByteArray(16 * 1024)
        var read = -1
        while (data.read(buffy).also { read = it } != -1) {
            signature.update(buffy, 0, read)
        }

        val signatureBytes = ByteArray(publicKey.modulus.bitLength() / 8)
        signData.read(signatureBytes)

        return signature.verify(signatureBytes)
    }

    private fun getData(): InputStream {
        return resources.openRawResource(R.raw.data)
    }

    private fun getPublicKeyReader(): PemReader {
        return PemReader(
            InputStreamReader(
                resources.openRawResource(R.raw.public_key)
            )
        )
    }

    private fun getSignature(): InputStream {
        return resources.openRawResource(R.raw.signature)
    }
}