package com.scottyab.ssl.util;


import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * <p>This class currently generates SSL pins based on a certificate's Subject Public Key Info as
 * described on <a href="https://www.imperialviolet.org/2011/05/04/pinning.html">Adam Langley's Weblog</a> (a.k.a Public Key pinning). Pins
 * are base-64 SHA-1 hashes, consistent with the format Chromium uses for <a
 * href="https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/http/transport_security_state_static.pins">static certificates</a>. See <a
 * href="https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/http/transport_security_state_static.json">Chromium's pinsets</a> for hostnames that are pinned in that
 * browser.
 * <p>
 * Designed to be compatible with okhttp 2.1+
 */
public class SSLPinGenerator {
    private static final String DEFAULT_HASH_ALGORTHM = "SHA-256";

    private final String hashAlgorthm;
    private final MessageDigest digest;
    private final String hostname;
    private final int hostPort;
    private final boolean debugPrinting;

    public SSLPinGenerator(String host, int port, String hashAlg, boolean argDebug) throws Exception {
        this.hashAlgorthm = hashAlg;
        this.hostname = host;
        this.hostPort = port;
        this.debugPrinting = argDebug;

        digest = MessageDigest.getInstance(hashAlg);
    }

    /**
     * @param args hostname (i.e android.com) and optionally port in form hostname:port, hash alg
     */
    public static void main(String[] args) {
        try {
            if (args.length >= 1) {

                if ("help".equalsIgnoreCase(args[0])) {
                    printHelp();
                    return;
                }

                String[] argHostAndPort = args[0].split(":");
                String argHost = argHostAndPort[0];

                // if port blank assume 443
                int argPort = (argHostAndPort.length == 1) ? 443 : Integer
                        .parseInt(argHostAndPort[1]);

                String argAlg;
                if (args.length >= 2) {
                    argAlg = args[1];
                } else {
                    argAlg = DEFAULT_HASH_ALGORTHM;
                }

                boolean argDebug = args.length >= 3 && ("debug".equalsIgnoreCase(args[2]));

                try {
                    SSLPinGenerator calc = new SSLPinGenerator(argHost, argPort, argAlg, argDebug);
                    calc.fetchAndPrintPinHashs();
                } catch (Exception e) {
                    printHelp();
                    System.out.println("\nWhoops something went wrong: " + e.getMessage());
                    e.printStackTrace();

                }
            } else {
                printHelp();
            }
        } catch (Exception e) {
            System.out.println("CLI Error: " + e.getMessage());
            printHelp();
        }
    }

    private static void printHelp() {
        System.out.println("##SSL pin set generator##");
        System.out.println("The generated pinset are base-64 encoded hashes (default SHA-256). Note: only run this on a trusted network.");
        System.out.println("\nUsage: \"SSLPinGenerator <host>[:port] hashAlgorthm\" i.e., scottyab.com:443 sha-256");
    }

    private void fetchAndPrintPinHashs() throws Exception {
        System.out.println("**Run this on a trusted network**\nGenerating SSL pins for: " + hostname);
        SSLContext context = SSLContext.getInstance("TLS");
        PublicKeyExtractingTrustManager tm = new PublicKeyExtractingTrustManager();
        context.init(null, new TrustManager[]{tm}, null);
        SSLSocketFactory factory = context.getSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket(hostname, hostPort);
        socket.setSoTimeout(10000);
        socket.startHandshake();
        socket.close();
    }

    /**
     * Calculates and prints hash of each certificate in the chain
     * <p>
     * PLEASE DO NOT COPY THIS TrustManager IMPLEMENTATION FOR USE IN REAL WORLD. This is just to print the pins.
     */
    public class PublicKeyExtractingTrustManager implements X509TrustManager {
        private final Base64.Encoder base64Encoder;
        private final List<X509Certificate> x509Certificates;

        public PublicKeyExtractingTrustManager() throws Exception {
            base64Encoder = Base64.getEncoder();
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            x509Certificates = new ArrayList<>();
            trustManagerFactory.init((KeyStore) null);
            Arrays.stream(trustManagerFactory.getTrustManagers()).forEach(trustManager ->
                    x509Certificates.addAll(Arrays.asList(((X509TrustManager) trustManager).getAcceptedIssuers())));
        }

        public X509Certificate[] getAcceptedIssuers() {
            //do nothing this is just to extract/print pins
            return null;
        }

        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            //do nothing this is just to extract/print pins
        }

        /**
         * receives the list of SSL certifications for a given connection
         */
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            String lastIssuer = null;
            int i = 0;
            for (X509Certificate cert : chain) {
                printPkp(cert, i++);
                lastIssuer = cert.getIssuerX500Principal().getName();
            }
            if (lastIssuer != null) {
                for (X509Certificate cert : x509Certificates) {
                    if (cert.getIssuerX500Principal().getName().equals(lastIssuer)) {
                        printPkp(cert, i++);
                    }
                }
            }
        }

        private void printPkp(X509Certificate cert, int i) {
            // We use the public key as it is consistent trough certificate renewals
            byte[] pubKey = cert.getPublicKey().getEncoded();
            String subject = cert.getSubjectX500Principal().getName();
            if (debugPrinting) {
                System.out.println(i + ". Subject :  " + subject);
                System.out.println("Expiry date :  " + cert.getNotAfter().toString());
            }
            final byte[] hash = digest.digest(pubKey);
            String hashAlgorthmWithoutHyphen = removeHyphenAndMakeLower(hashAlgorthm);
            System.out.printf(Locale.ROOT, "%s/%s%n", hashAlgorthmWithoutHyphen, base64Encoder.encodeToString(hash));
        }

        private String removeHyphenAndMakeLower(String hashAlgorthm) {
            return hashAlgorthm.replace("-", "").toLowerCase(Locale.ROOT);
        }
    }

}
