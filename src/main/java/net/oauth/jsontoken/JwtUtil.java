/*
 * Copyright 2015 Network New Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.oauth.jsontoken;

import net.oauth.jsontoken.crypto.HmacSHA256Signer;
import net.oauth.jsontoken.crypto.HmacSHA256Verifier;
import net.oauth.jsontoken.crypto.SignatureAlgorithm;
import net.oauth.jsontoken.crypto.Verifier;
import net.oauth.jsontoken.discovery.VerifierProvider;
import net.oauth.jsontoken.discovery.VerifierProviders;
import net.oauth.signatures.SignedTokenAudienceChecker;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by steve on 14/09/14.
 */
public class JwtUtil {
    final static String ISSUER = "networknt.com";
    final static String SIGNING_KEY = "1293089278894893893";
    public static String TOKEN_EXPIRED_MESSAGE = "Invalid iat and/or exp.";

    static VerifierProviders verifierProviders = null;
    static{
        try {
            final Verifier hmacVerifier = new HmacSHA256Verifier(SIGNING_KEY.getBytes());
            VerifierProvider hmacLocator = new VerifierProvider() {
                @Override
                public List<Verifier> findVerifier(String signerId, String keyId) {
                    List<Verifier> list = new ArrayList<Verifier>();
                    list.add(hmacVerifier);
                    return list;
                }
            };
            verifierProviders = new VerifierProviders();
            verifierProviders.setVerifierProvider(SignatureAlgorithm.HS256, hmacLocator);

        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {
        String jwt = null;
        if(args != null && args.length == 1) {
            jwt = args[0];
            if(jwt.length() == 0 ) {
                System.out.println("jwt is required");
                System.exit(1);
            }
        } else {
            System.out.println("Usage: JwtUtil jsontoken");
            System.exit(1);
        }
        System.out.println("jwt = " + jwt);
        JsonToken token = Deserialize(jwt);
        System.out.println("token = " + token);
        token = VerifyAndDeserialize(jwt);
        System.out.println("token = " + token);
    }

    public static JsonToken Deserialize(String jwt) throws Exception {
        JsonTokenParser parser = new JsonTokenParser(verifierProviders, new SignedTokenAudienceChecker("networknt.com"));
        return parser.deserialize(jwt);
    }
    public static JsonToken VerifyAndDeserialize(String jwt) throws Exception {
        JsonTokenParser parser = new JsonTokenParser(verifierProviders, new SignedTokenAudienceChecker("networknt.com"));
        return parser.verifyAndDeserialize(jwt);
    }
}
