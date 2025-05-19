package org.tinyradius.packet;

import org.tinyradius.attribute.RadiusAttribute;
import org.tinyradius.attribute.StringAttribute;
import org.tinyradius.util.Authenticator;
import org.tinyradius.util.RadiusException;
import org.tinyradius.util.RadiusUtil;
import net.sf.jradius.util.MSCHAP;
import net.sf.jradius.util.RadiusUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * This class represents an Access-Request Radius packet.
 */
public class AccessRequest extends RadiusPacket {

    public static final int NT_DIGEST_LENGTH = 16;
    
    /**
     * Passphrase Authentication Protocol
     */
    public static final String AUTH_PAP = "pap";

    /**
     * Challenged Handshake Authentication Protocol
     */
    public static final String AUTH_CHAP = "chap";

    /**
     * MSCHAP-V2 See: https://tools.ietf.org/html/rfc2759 and
     * https://tools.ietf.org/html/rfc2548
     */
    public static final String AUTH_MSCHAPV2 = "mschap-v2";

    public static final String AUTH_MSCHAPV1 = "mschap-v1";

    /**
     * Microsoft Radius Vendor ID
     */
    private static final int MS_VENDOR_ID = 311;

    /**
     * Constructs an empty Access-Request packet.
     */
    public AccessRequest() {
        super(ACCESS_REQUEST);
    }

    /**
     * Constructs an Access-Request packet, sets the code, identifier and adds
     * an RadUser-Name and an RadUser-Password attribute (PAP).
     *
     * @param userName user name
     * @param userPassword user password
     */
    public AccessRequest(String userName, String userPassword) {
        super(ACCESS_REQUEST, getNextPacketIdentifier());
        setUserName(userName);
        setUserPassword(userPassword);
    }

    /**
     * Sets the RadUser-Name attribute of this Access-Request.
     *
     * @param userName user name to set
     */
    public void setUserName(String userName) {
        if (userName == null) {
            throw new NullPointerException("user name not set");
        }
        if (userName.length() == 0) {
            throw new IllegalArgumentException("empty user name not allowed");
        }

        removeAttributes(USER_NAME);
        addAttribute(new StringAttribute(USER_NAME, userName));
    }

    /**
     * Sets the plain-text user password.
     *
     * @param userPassword user password to set
     */
    public void setUserPassword(String userPassword) {
        if (userPassword == null || userPassword.length() == 0) {
            throw new IllegalArgumentException("password is empty");
        }
        this.password = userPassword;
    }

    /**
     * Retrieves the plain-text user password. Returns null for CHAP - use
     * verifyPassword().
     *
     * @see #verifyPassword(String)
     * @return user password
     */
    public String getUserPassword() {
        return password;
    }

    public byte[] getChapChallenge() {
        return chapChallenge;
    }

    public byte[] getPeerChallenge() {
        return peerChallenge;
    }

    public byte[] getNtResponse() {
        return ntResponse;
    }

    public byte[] getLmResponse() {
        return lmResponse;
    }
    
    /**
     * Retrieves the user name from the RadUser-Name attribute.
     *
     * @return user name
     */
    public String getUserName() {
        List attrs = getAttributes(USER_NAME);
        if (attrs.size() < 1 || attrs.size() > 1) {
            throw new RuntimeException("exactly one RadUser-Name attribute required");
        }

        RadiusAttribute ra = (RadiusAttribute) attrs.get(0);
        return ((StringAttribute) ra).getAttributeValue();
    }

    /**
     * Returns the protocol used for encrypting the passphrase.
     *
     * @return AUTH_PAP or AUTH_CHAP
     */
    public String getAuthProtocol() {
        return authProtocol;
    }

    /**
     * Selects the protocol to use for encrypting the passphrase when encoding
     * this Radius packet.
     *
     * @param authProtocol AUTH_PAP or AUTH_CHAP
     */
    public void setAuthProtocol(String authProtocol) {
        if (authProtocol != null
                && (authProtocol.equals(AUTH_PAP)
                || authProtocol.equals(AUTH_CHAP)
                || authProtocol.equals(AUTH_MSCHAPV1)
                || authProtocol.equals(AUTH_MSCHAPV2))) {
            this.authProtocol = authProtocol;
        } else {
            throw new IllegalArgumentException("protocol must be pap or chap");
        }
    }

    /**
     * Verifies that the passed plain-text password matches the password (hash)
     * send with this Access-Request packet. Works with both PAP and CHAP.
     *
     * @param plaintext
     * @return true if the password is valid, false otherwise
     */
    public boolean verifyPassword(String plaintext) throws RadiusException {
        if (plaintext == null || plaintext.length() == 0) {
            throw new IllegalArgumentException("password is empty");
        }
        if (getAuthProtocol().equals(AUTH_CHAP)) {
            return verifyChapPassword(plaintext);
        } else if (AUTH_MSCHAPV2.equals(getAuthProtocol())) {
            return verifyMSChapV2Password(plaintext);
        } else if (AUTH_MSCHAPV1.equals(getAuthProtocol())) {
            return verifyMSChapV1Password(plaintext);
        }
        return getUserPassword().equals(plaintext);
    }

    
    /**
     * Verify that an MSCHAPV1 password is valid
     *
     * @param password
     * @return
     */
    public boolean verifyMSChapV1Password(String password) {
        switch(ntOnly) {
            case 0x01: {
                String ntResponse = RadiusUtils.byteArrayToHexString(getNtResponse());
                String passwordNtResponse = RadiusUtils.byteArrayToHexString(MSCHAP.NtChallengeResponse(getChapChallenge(),  password.getBytes()));
                return ntResponse.equals(passwordNtResponse);
            }
            case 0x00: {
                String lmResponse = RadiusUtils.byteArrayToHexString(getLmResponse());
                String passwordLmResponse = RadiusUtils.byteArrayToHexString(MSCHAP.LmChallengeResponse(getChapChallenge(),  password.getBytes()));
                return lmResponse.equals(passwordLmResponse);
            }
        }
        
        return false;
    }
    
    
    
    /**
     * Verify that an MSCHAPV2 password is valid
     *
     * @param password
     * @return
     */
    public boolean verifyMSChapV2Password(String password) {
        String ntResponse = RadiusUtils.byteArrayToHexString(getNtResponse());
        String passwordNtResponse = RadiusUtils.byteArrayToHexString(MSCHAP.GenerateNTResponse(getChapChallenge(), getPeerChallenge(), getUserName().getBytes(), password.getBytes()));

//		System.err.println("ntResponse (" + ntResponse + ")");
//		System.err.println("passwordNtResponse (" + passwordNtResponse + ")");
        return ntResponse.equals(passwordNtResponse);
    }

    
    
    /**
     * Creates an MSCHAPV1 response
     */
    
    


    public void addMSCHAPV1Response(RadiusPacket responsePacket, String password, String secret) {
        if (!AUTH_MSCHAPV1.equals(getAuthProtocol())) {
            return;
        }
        byte[] mppe_sendkey = new byte[32];
        byte[] ntHashHash = Authenticator.getPasswordHashHash(password.getBytes());
        
        
        //memset(mppe_sendkey, 0, 32);
        Arrays.fill(mppe_sendkey, (byte)0x00);
        //memcpy(mppe_sendkey + 8, nthashhash, NT_DIGEST_LENGTH );
        System.arraycopy(ntHashHash, 0, mppe_sendkey, 8, NT_DIGEST_LENGTH );
        
        
        responsePacket.addOctetAttribute("MS-CHAP-MPPE-Keys",encodePapPassword(mppe_sendkey, RadiusUtil.getUtf8Bytes(secret)));
        responsePacket.addAttribute("MS-MPPE-Encryption-Policy", new String(new byte[]{0x00, 0x00, 0x00, 0x02}));
        responsePacket.addAttribute("MS-MPPE-Encryption-Type", new String(new byte[]{0x00, 0x00, 0x00, 0x04}));
        
        
    }
    
    
    /*

        /* now create MPPE attributes 
        if (inst->use_mppe) {
                uint8_t mppe_sendkey[34];
                uint8_t mppe_recvkey[34];

                if (mschap_version == 1) {
                        RDEBUG2("adding MS-CHAPv1 MPPE keys");
                        memset(mppe_sendkey, 0, 32);

                        /*
                         *      According to RFC 2548 we
                         *      should send NT hash.  But in
                         *      practice it doesn't work.
                         *      Instead, we should send nthashhash
                         *
                         *      This is an error in RFC 2548.
                         
                        /*
                         *      do_mschap cares to zero nthashhash if NT hash
                         *      is not available.


                        memcpy(mppe_sendkey + 8, nthashhash, NT_DIGEST_LENGTH );
                        mppe_add_reply(request, "MS-CHAP-MPPE-Keys", mppe_sendkey, 24);

                } else if (mschap_version == 2) {
                        RDEBUG2("Adding MS-CHAPv2 MPPE keys");
                        mppe_chap2_gen_keys128(nthashhash, response->vp_octets + 26, mppe_sendkey, mppe_recvkey);

                        mppe_add_reply(request, "MS-MPPE-Recv-Key", mppe_recvkey, 16);
                        mppe_add_reply(request, "MS-MPPE-Send-Key", mppe_sendkey, 16);

                }
                pair_make_reply("MS-MPPE-Encryption-Policy",
                               (inst->require_encryption) ? "0x00000002":"0x00000001", T_OP_EQ);
                pair_make_reply("MS-MPPE-Encryption-Types",
                               (inst->require_strong) ? "0x00000004":"0x00000006", T_OP_EQ);
        } /* else we weren't asked to use MPPE 
    
    */
    
    
    /**
     * Creates an MSCHAPV2 response
     */
    public void addMSCHAPV2Response(RadiusPacket responsePacket, String password, String secret) {
        if (!AUTH_MSCHAPV2.equals(getAuthProtocol())) {
            return;
        }
        String successResponse = createMSCHAPV2Response(getUserName(), password.getBytes(), (byte) 0x01, getNtResponse(), getPeerChallenge(), getChapChallenge());
        responsePacket.addAttribute("MS-CHAP2-Success", successResponse);

        responsePacket.addAttribute("MS-MPPE-Encryption-Policy", new String(new byte[]{0x00, 0x00, 0x00, 0x02}));
        responsePacket.addAttribute("MS-MPPE-Encryption-Type", new String(new byte[]{0x00, 0x00, 0x00, 0x04}));

//		System.err.println("ntResponse (" + RadiusUtils.byteArrayToHexString(ntResponse) + ")");
        byte[] ntHashHash = Authenticator.getPasswordHashHash(password.getBytes());
        byte[] mppeSendKey = RadiusUtil.mppeCHAP2GenKeySend128(ntHashHash, getNtResponse());
        byte[] mppeRecvKey = RadiusUtil.mppeCHAP2GenKeyRecv128(ntHashHash, getNtResponse());

//		System.err.println("mppeSendKey (" + RadiusUtils.byteArrayToHexString(mppeSendKey) + ")");
//		System.err.println("mppeRecvKey (" + RadiusUtils.byteArrayToHexString(mppeRecvKey) + ")");
        byte[] mppeSendKeyEncoded = RadiusUtil.generateEncryptedMPPEPassword(mppeSendKey, 1024, secret.getBytes(), getAuthenticator());
        byte[] mppeRecvKeyEncoded = RadiusUtil.generateEncryptedMPPEPassword(mppeRecvKey, 1024, secret.getBytes(), getAuthenticator());

        responsePacket.addOctetAttribute("MS-MPPE-Send-Key", mppeSendKeyEncoded);
        responsePacket.addOctetAttribute("MS-MPPE-Recv-Key", mppeRecvKeyEncoded);
    }

    /**
     * Creates an MSCHAPV2 success response
     *
     * @param username
     * @param password
     * @param ident
     * @param ntResponse
     * @param peerChallenge
     * @param authenticator
     * @return
     */
    protected String createMSCHAPV2Response(String username, byte[] password, byte ident, byte[] ntResponse, byte[] peerChallenge, byte[] authenticator) {
        byte[] authResponse = Authenticator.GenerateAuthenticatorResponse(
                password,
                ntResponse,
                peerChallenge,
                authenticator,
                username.getBytes()
        );

//		System.err.println("authResponse (" + RadiusUtils.byteArrayToHexString(authResponse) + ")");
        String successResponse
                = (char) ident
                + "S="
                + RadiusUtils.byteArrayToHexString(authResponse).toUpperCase();

//		System.err.println("successResponse (" + successResponse + ")");
        return successResponse;
    }



    protected byte ntOnlyMSCHAPV1Response(byte[] attributeData) throws RadiusException {
        return attributeData[1];
    }


    protected List<byte[]> decodeMSCHAPV1Response(byte[] attributeData) throws RadiusException {
        List<byte[]> responseComponents = new ArrayList<byte[]>();

        responseComponents.add(getMSCHAPV1LmPassword(attributeData));
        responseComponents.add(getMSCHAPV1NtPassword(attributeData));

        return responseComponents;
    }
    

    private byte[] getMSCHAPV1LmPassword(byte[] attributeData) throws RadiusException {
        validateMSCHAPResponseAttribute(attributeData);

        int pStart = 2;
        int pLength = 24;

        return copyBytes(attributeData, pStart, pLength);
    }
    private byte[] getMSCHAPV1NtPassword(byte[] attributeData) throws RadiusException {
        validateMSCHAPResponseAttribute(attributeData);

        int pStart = 26;
        int pLength = 24;

        return copyBytes(attributeData, pStart, pLength);
    }


    protected List<byte[]> decodeMSCHAPV2Response(byte[] attributeData) throws RadiusException {
        List<byte[]> responseComponents = new ArrayList<byte[]>();

        responseComponents.add(getMSCHAPV2Password(attributeData));
        responseComponents.add(getMSCHAPV2PeerChallenge(attributeData));

        return responseComponents;
    }

    private byte[] getMSCHAPV2PeerChallenge(byte[] attributeData) throws RadiusException {
        validateMSCHAPResponseAttribute(attributeData);

        int pcStart = 2;
        int pcLength = 16;
        return copyBytes(attributeData, pcStart, pcLength);
    }

    private byte[] getMSCHAPV2Password(byte[] attributeData) throws RadiusException {
        validateMSCHAPResponseAttribute(attributeData);

        int pStart = 26;
        int pLength = 24;

        return copyBytes(attributeData, pStart, pLength);
    }

    private byte[] copyBytes(byte[] attributeData, int start, int length) {
        byte[] rv = new byte[length];
        for (int i = start, j = 0; i < (start + length); i++, j++) {
            rv[j] = attributeData[i];
        }

        return rv;
    }

    private void validateMSCHAPResponseAttribute(byte[] attributeData) throws RadiusException {
        // check this is a MS-CHAP2-Response packet
        if (attributeData.length != 50) {
            throw new RadiusException("Invalid MSCHAPV2-Response attribute length");
        }
/*
        int vendorType = new Integer(attributeData[0]);
        if (vendorType != 25 && vendorType != 1) {
			throw new RadiusException("Invalid MSCHAPV2-Response attribute type");
        }
 */
        }

    /**
     * Decrypts the RadUser-Password attribute.
     *
     * @see RadiusPacket#decodeRequestAttributes(String)
     */
    @Override
    protected void decodeRequestAttributes(String sharedSecret) throws RadiusException {
        // detect auth protocol
        RadiusAttribute userPassword = getAttribute(USER_PASSWORD);
        RadiusAttribute chapPassword = getAttribute(CHAP_PASSWORD);
        RadiusAttribute chapChallenge = getAttribute(CHAP_CHALLENGE);

        RadiusAttribute mschapv2Response = getVendorAttribute(MS_VENDOR_ID, MSCHAPV2_RESPONSE);
        RadiusAttribute mschapChallenge = getVendorAttribute(MS_VENDOR_ID, MSCHAP_CHALLENGE);
        RadiusAttribute mschapv1Response = getVendorAttribute(MS_VENDOR_ID, MSCHAP_RESPONSE);

        if (userPassword != null) {
            setAuthProtocol(AUTH_PAP);
            this.password = decodePapPassword(userPassword.getAttributeData(), RadiusUtil.getUtf8Bytes(sharedSecret));
            // copy truncated data
            userPassword.setAttributeData(RadiusUtil.getUtf8Bytes(this.password));
        } else if (mschapv2Response != null && mschapChallenge != null) {
            setAuthProtocol(AUTH_MSCHAPV2);
            this.chapChallenge = mschapChallenge.getAttributeData();
            if (chapPassword != null) {
                this.chapPassword = chapPassword.getAttributeData();
            }

            List<byte[]> responseComponents = decodeMSCHAPV2Response(mschapv2Response.getAttributeData());
            this.ntResponse = responseComponents.get(0);
            this.peerChallenge = responseComponents.get(1);
        } else if (mschapv1Response != null && mschapChallenge != null) {
            setAuthProtocol(AUTH_MSCHAPV1);
            this.chapChallenge = mschapChallenge.getAttributeData();
            if (chapPassword != null) {
                this.chapPassword = chapPassword.getAttributeData();
            }

            List<byte[]> responseComponents = decodeMSCHAPV1Response(mschapv1Response.getAttributeData());
            this.ntOnly = ntOnlyMSCHAPV1Response(mschapv1Response.getAttributeData());
            this.lmResponse = responseComponents.get(0);
            this.ntResponse = responseComponents.get(1);
        } else if (chapPassword != null && chapChallenge != null) {
            setAuthProtocol(AUTH_CHAP);
            this.chapPassword = chapPassword.getAttributeData();
            this.chapChallenge = chapChallenge.getAttributeData();
        } else if (chapPassword != null && getAuthenticator().length == 16) {
            // thanks to Guillaume Tartayre
            setAuthProtocol(AUTH_CHAP);
            this.chapPassword = chapPassword.getAttributeData();
            this.chapChallenge = getAuthenticator();
        } else {
            throw new RadiusException("Access-Request: RadUser-Password or CHAP-Password/CHAP-Challenge missing");
        }
    }

    
    /**
     * Sets and encrypts the RadUser-Password attribute.
     *
     * @see RadiusPacket#encodeRequestAttributes(String)
     */
    @Override
    protected void encodeRequestAttributes(String sharedSecret) {
        if (password == null || password.length() == 0) {
            return;
        }
        // ok for proxied packets whose CHAP password is already encrypted
        // throw new RuntimeException("no password set");
        if (getPacketType() != ACCESS_ACCEPT) {
            if (getAuthProtocol().equals(AUTH_PAP)) {
                byte[] pass = encodePapPassword(RadiusUtil.getUtf8Bytes(this.password), RadiusUtil.getUtf8Bytes(sharedSecret));
                removeAttributes(USER_PASSWORD);
                addAttribute(new RadiusAttribute(USER_PASSWORD, pass));
            } else if (getAuthProtocol().equals(AUTH_CHAP)) {
                byte[] challenge = createChapChallenge();
                byte[] pass = encodeChapPassword(password, challenge);
                removeAttributes(CHAP_PASSWORD);
                removeAttributes(CHAP_CHALLENGE);
                addAttribute(new RadiusAttribute(CHAP_PASSWORD, pass));
                addAttribute(new RadiusAttribute(CHAP_CHALLENGE, challenge));
            } else if (AUTH_MSCHAPV2.equals(getAuthProtocol())) {
                String username = getUserName();
                if (username == null) {
                    throw new IllegalArgumentException("Username required");
                }
                byte[] challenge = createChapChallenge();
                byte[] response = MSCHAP.doMSCHAPv2(username.getBytes(), password.getBytes(), challenge);
                removeAttributes(MS_VENDOR_ID, MSCHAP_CHALLENGE);
                removeAttributes(MS_VENDOR_ID, MSCHAPV2_RESPONSE);
                addOctetAttribute("MS-CHAP-Challenge", challenge);
                addOctetAttribute("MS-CHAP2-Response", response);
            } else if (AUTH_MSCHAPV1.equals(getAuthProtocol())) {
                byte[] challenge = createChapChallenge();
                byte[] response = MSCHAP.doMSCHAPv1(password.getBytes(), challenge);
                removeAttributes(MS_VENDOR_ID, MSCHAP_CHALLENGE);
                removeAttributes(MS_VENDOR_ID, MSCHAP_RESPONSE);
                addOctetAttribute("MS-CHAP-Challenge", challenge);
                addOctetAttribute("MS-CHAP-Response", response);
            }
        }

    }

    
    /**
     * This method encodes the plaintext user password according to RFC 2865.
     *
     * @param userPass the password to encrypt
     * @param sharedSecret shared secret
     * @return the byte array containing the encrypted password
     */
    private byte[] encodePapPassword(final byte[] userPass, byte[] sharedSecret) {
        // the password must be a multiple of 16 bytes and less than or equal
        // to 128 bytes. If it isn't a multiple of 16 bytes fill it out with zeroes
        // to make it a multiple of 16 bytes. If it is greater than 128 bytes
        // truncate it at 128.
        byte[] userPassBytes = null;
        if (userPass.length > 128) {
            userPassBytes = new byte[128];
            System.arraycopy(userPass, 0, userPassBytes, 0, 128);
        } else {
            userPassBytes = userPass;
        }

        // declare the byte array to hold the final product
        byte[] encryptedPass = null;
        if (userPassBytes.length < 128) {
            if (userPassBytes.length % 16 == 0) {
                // tt is already a multiple of 16 bytes
                encryptedPass = new byte[userPassBytes.length];
            } else {
                // make it a multiple of 16 bytes
                encryptedPass = new byte[((userPassBytes.length / 16) * 16) + 16];
            }
        } else {
            // the encrypted password must be between 16 and 128 bytes
            encryptedPass = new byte[128];
        }

        // copy the userPass into the encrypted pass and then fill it out with zeroes by default.
        System.arraycopy(userPassBytes, 0, encryptedPass, 0, userPassBytes.length);

        // digest shared secret and authenticator
        MessageDigest md5 = getMd5Digest();

        // According to section-5.2 in RFC 2865, when the password is longer than 16
        // characters: c(i) = pi xor (MD5(S + c(i-1)))
        for (int i = 0; i < encryptedPass.length; i += 16) {
            md5.reset();
            md5.update(sharedSecret);
            if (i == 0) {
                md5.update(getAuthenticator());
            } else {
                md5.update(encryptedPass, i - 16, 16);
            }

            byte bn[] = md5.digest();

            // perform the XOR as specified by RFC 2865.
            for (int j = 0; j < 16; j++) {
                encryptedPass[i + j] = (byte) (bn[j] ^ encryptedPass[i + j]);
            }
        }
        return encryptedPass;
    }

    /**
     * Decodes the passed encrypted password and returns the clear-text form.
     *
     * @param encryptedPass encrypted password
     * @param sharedSecret shared secret
     * @return decrypted password
     */
    private String decodePapPassword(byte[] encryptedPass, byte[] sharedSecret) throws RadiusException {
        if (encryptedPass == null || encryptedPass.length < 16) {
            // PAP passwords require at least 16 bytes
            logger.warn("invalid Radius packet: RadUser-Password attribute with malformed PAP password, length = "
                    + (encryptedPass == null ? 0 : encryptedPass.length) + ", but length must be greater than 15");
            throw new RadiusException("malformed RadUser-Password attribute");
        }

        MessageDigest md5 = getMd5Digest();
        byte[] lastBlock = new byte[16];

        for (int i = 0; i < encryptedPass.length; i += 16) {
            md5.reset();
            md5.update(sharedSecret);
            md5.update(i == 0 ? getAuthenticator() : lastBlock);
            byte bn[] = md5.digest();

            System.arraycopy(encryptedPass, i, lastBlock, 0, 16);

            // perform the XOR as specified by RFC 2865.
            for (int j = 0; j < 16; j++) {
                encryptedPass[i + j] = (byte) (bn[j] ^ encryptedPass[i + j]);
            }
        }

        // remove trailing zeros
        int len = encryptedPass.length;
        while (len > 0 && encryptedPass[len - 1] == 0) {
            len--;
        }
        byte[] passtrunc = new byte[len];
        System.arraycopy(encryptedPass, 0, passtrunc, 0, len);

        // convert to string
        return RadiusUtil.getStringFromUtf8(passtrunc);
    }

    /**
     * Creates a random CHAP challenge using a secure random algorithm.
     *
     * @return 16 byte CHAP challenge
     */
    private byte[] createChapChallenge() {
        byte[] challenge = new byte[16];
        random.nextBytes(challenge);
        return challenge;
    }

    /**
     * Encodes a plain-text password using the given CHAP challenge.
     *
     * @param plaintext plain-text password
     * @param chapChallenge CHAP challenge
     * @return CHAP-encoded password
     */
    private byte[] encodeChapPassword(String plaintext, byte[] chapChallenge) {
        // see RFC 2865 section 2.2
        byte chapIdentifier = (byte) random.nextInt(256);
        byte[] chapPassword = new byte[17];
        chapPassword[0] = chapIdentifier;

        MessageDigest md5 = getMd5Digest();
        md5.reset();
        md5.update(chapIdentifier);
        md5.update(RadiusUtil.getUtf8Bytes(plaintext));
        byte[] chapHash = md5.digest(chapChallenge);

        System.arraycopy(chapHash, 0, chapPassword, 1, 16);
        return chapPassword;
    }

    /**
     * Verifies a CHAP password against the given plaintext password.
     *
     * @return plain-text password
     */
    private boolean verifyChapPassword(String plaintext) throws RadiusException {
        if (plaintext == null || plaintext.length() == 0) {
            throw new IllegalArgumentException("plaintext must not be empty");
        }
        if (chapChallenge == null || chapChallenge.length != 16) {
            throw new RadiusException("CHAP challenge must be 16 bytes");
        }
        if (chapPassword == null || chapPassword.length != 17) {
            throw new RadiusException("CHAP password must be 17 bytes");
        }

        byte chapIdentifier = chapPassword[0];
        MessageDigest md5 = getMd5Digest();
        md5.reset();
        md5.update(chapIdentifier);
        md5.update(RadiusUtil.getUtf8Bytes(plaintext));
        byte[] chapHash = md5.digest(chapChallenge);

        // compare
        for (int i = 0; i < 16; i++) {
            if (chapHash[i] != chapPassword[i + 1]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Temporary storage for the unencrypted RadUser-Password attribute.
     */
    private String password;

    /**
     * Authentication protocol for this access request.
     */
    private String authProtocol = AUTH_PAP;

    /**
     * CHAP password from a decoded CHAP Access-Request.
     */
    private byte[] chapPassword;

    /**
     * Random generator
     */
    private static SecureRandom random = new SecureRandom();

    /**
     * Radius type code for Radius attribute RadUser-Name
     */
    private static final int USER_NAME = 1;

    /**
     * Radius attribute type for RadUser-Password attribute.
     */
    private static final int USER_PASSWORD = 2;

    /**
     * Radius attribute type for CHAP-Password attribute.
     */
    private static final int CHAP_PASSWORD = 3;

    /**
     * Radius attribute type for CHAP-Challenge attribute.
     */
    private static final int CHAP_CHALLENGE = 60;

    /**
     * Radius attribute type for MSCHAP-v2 Challenge attribute
     */
    private static final int MSCHAP_CHALLENGE = 11;

    /**
     * Radius attribute type for MSCHAP-v2 Response attribute
     */
    private static final int MSCHAPV2_RESPONSE = 25;

    /**
     * Radius attribute type for MSCHAP Response attribute
     */
    private static final int MSCHAP_RESPONSE = 1;
    
    /*
    
VENDORATTR      311   MS-CHAP-Response 1        octets
VENDORATTR      311   MS-CHAP-Challenge 11      octets
VENDORATTR      311   MS-CHAP-MPPE-Keys 12      octets
VENDORATTR      311   MS-MPPE-Send-Key 16       octet
VENDORATTR      311   MS-MPPE-Recv-Key 17       octet
VENDORATTR      311   MS-CHAP2-Response 25      octets
VENDORATTR      311   MS-CHAP2-Success 26       string

    */
    
    /**
     * CHAP challenge from a decoded CHAP Access-Request.
     */
    private byte[] chapChallenge;

    /**
     * Peer Challenge from a decoded MSCHAPV2 Access-Request
     */
    private byte[] peerChallenge;

    /**
     * NTResponse for MSCHAPV2
     */
    private byte[] ntResponse;

    /**
     * LMResponse for MSCHAPV1
     */
    private byte[] lmResponse;

    private byte ntOnly = 0x00;

    /**
     * Logger for logging information about malformed packets
     */
    private static Logger logger = LoggerFactory.getLogger(AccessRequest.class);

}
