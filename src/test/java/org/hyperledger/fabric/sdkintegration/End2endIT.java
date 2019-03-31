/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.hyperledger.fabric.sdkintegration;
import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.Set;
import java.util.Vector;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.openssl.PEMWriter;
import org.hyperledger.fabric.protos.ledger.rwset.kvrwset.KvRwset;
import org.hyperledger.fabric.sdk.*;
import org.hyperledger.fabric.sdk.Peer.PeerRole;
import org.hyperledger.fabric.sdk.TransactionRequest.Type;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.InvalidProtocolBufferRuntimeException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.exception.TransactionEventException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.testutils.TestConfig;
import org.hyperledger.fabric_ca.sdk.EnrollmentRequest;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.HFCAInfo;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.junit.Before;
import org.junit.Test;
import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hyperledger.fabric.sdk.BlockInfo.EnvelopeType.TRANSACTION_ENVELOPE;
import static org.hyperledger.fabric.sdk.Channel.NOfEvents.createNofEvents;
import static org.hyperledger.fabric.sdk.Channel.PeerOptions.createPeerOptions;
import static org.hyperledger.fabric.sdk.Channel.TransactionOptions.createTransactionOptions;
import static org.hyperledger.fabric.sdk.testutils.TestUtils.resetConfig;
import static org.hyperledger.fabric.sdk.testutils.TestUtils.testRemovingAddingPeersOrderers;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
/**
 * Test end to end scenario
 */
public class End2endIT {
    //创建测试的配置类,这里第一次运行其实是new了一个
    private static final TestConfig testConfig = TestConfig.getConfig();
    //测试的管理员账号
    static final String TEST_ADMIN_NAME = "admin";
    //测试的路径
    private static final String TEST_FIXTURES_PATH = "src/test/fixture";
    private static Random random = new Random();
    //两个channel的名字
    private static final String FOO_CHANNEL_NAME = "foo";
    private static final String BAR_CHANNEL_NAME = "bar";
    //部署的等待时间
    private static final int DEPLOYWAITTIME = testConfig.getDeployWaitTime();
    //期待的事件数据此处是!
    private static final byte[] EXPECTED_EVENT_DATA = "!".getBytes(UTF_8);
    //期待的事件名字
    private static final String EXPECTED_EVENT_NAME = "event";
    private static final Map<String, String> TX_EXPECTED;
    //要测试的名字,每个测试都有一个名字
    String testName = "End2endIT";
    //链码的文件路径
    String CHAIN_CODE_FILEPATH = "sdkintegration/gocc/sample1";
    //链码的名字
    String CHAIN_CODE_NAME = "example_cc_go";
    //链码路径
    String CHAIN_CODE_PATH = "github.com/example_cc";
    //链码的版本
    String CHAIN_CODE_VERSION = "1";
    //链码的语言类型,此处是GO语言
    Type CHAIN_CODE_LANG = Type.GO_LANG;
    //静态代码块初始化一些值,此处初始化了TX_EXPECTED
    static {
        TX_EXPECTED = new HashMap<>();
        TX_EXPECTED.put("readset1", "Missing readset for channel bar block 1");
        TX_EXPECTED.put("writeset1", "Missing writeset for channel bar block 1");
    }
    //创建测试配置文件帮助类
    private final TestConfigHelper configHelper = new TestConfigHelper();
    //定义变量用来保存TxID,后续会用来进行查询
    String testTxID = null;  // save the CC invoke TxID and use in queries
    //创建1个本地键值对存储的类,此时是空的还没有初始化
    SampleStore sampleStore = null;
    //建立一个数组,里面存储的内容是组织的简单描述
    private Collection<SampleOrg> testSampleOrgs;
    //测试用户user1
    static String testUser1 = "user1";
    /**
     * 格式化一些输出语句
     * @param format
     * @param args
     */
    static void out(String format, Object... args) {
        System.err.flush();
        System.out.flush();
        System.out.println(format(format, args));
        System.err.flush();
        System.out.flush();
    }
    //CHECKSTYLE.ON: Method length is 320 lines (max allowed is 150).
    static String printableString(final String string) {
        int maxLogStringLength = 64;
        if (string == null || string.length() == 0) {
            return string;
        }
        String ret = string.replaceAll("[^\\p{Print}]", "?");
        ret = ret.substring(0, Math.min(ret.length(), maxLogStringLength)) + (ret.length() > maxLogStringLength ? "..." : "");
        return ret;
    }
    /**
     * 测试之前检查配置的方法
     * @throws NoSuchFieldException
     * @throws SecurityException
     * @throws IllegalArgumentException
     * @throws IllegalAccessException
     * @throws MalformedURLException
     * @throws org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException
     */
    @Before
    public void checkConfig() throws NoSuchFieldException, SecurityException,
            IllegalArgumentException, IllegalAccessException, MalformedURLException,
            org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException {
        out("\n\n\nRUNNING: %s.\n", testName);
        //   configHelper.clearConfig();
        //   assertEquals(256, Config.getConfig().getSecurityLevel());
        //首先重制配置文件
        resetConfig();
        //初始化自定义的配置帮助类,该方法会向系统变量放入一些键值对
        configHelper.customizeConfig();
        //获得整合的测试的简单组织Orgs
        testSampleOrgs = testConfig.getIntegrationTestsSampleOrgs();
        //Set up hfca for each sample org
        //循环遍历上面获取到的组织信息
        for (SampleOrg sampleOrg : testSampleOrgs) {
            System.out.println("获取到的每一个示例组织信息是sampleOrg="+sampleOrg);
            //这个时候的SampleOrg还没有设置CAClient的字段
            //获取每一个组织的caName
            String caName = sampleOrg.getCAName(); //Try one of each name and no name.
            //如果caName不是空的时候
            if (caName != null && !caName.isEmpty()) {
                System.out.println("caName不是空的通过caName设置设置CAClient");
                //设置CAClient,参数为caName,以及caName的url地址和Properties配置文件
                sampleOrg.setCAClient(HFCAClient.createNewInstance(caName, sampleOrg.getCALocation(), sampleOrg.getCAProperties()));
            } else {
                //由于caName是空因此和上面比较起来少了caName参数,剩余的参数是一样的
                sampleOrg.setCAClient(HFCAClient.createNewInstance(sampleOrg.getCALocation(), sampleOrg.getCAProperties()));
            }
        }
    }
    Map<String, Properties> clientTLSProperties = new HashMap<>();
    File sampleStoreFile = new File(System.getProperty("java.io.tmpdir") + "/HFCSampletest.properties");
    @Test
    public void setup() throws Exception {
        //Persistence is not part of SDK. Sample file store is for demonstration purposes only!
        //   MUST be replaced with more robust application implementation  (Database, LDAP)
        //每一次测试都要判断该文件是否存在,如果存在就删除
        if (sampleStoreFile.exists()) { //For testing start fresh
            sampleStoreFile.delete();
        }
        //新创建例子的存储
        sampleStore = new SampleStore(sampleStoreFile);
        System.out.println("示例存储的内容是sampleStore="+sampleStore);
        //用户背书的步骤？？？、这将使用Fabric CA注册用户,并设置示例存储,以便稍后获取用户
        enrollUsersSetup(sampleStore); //This enrolls users with fabric ca and setups sample store to get users later.
        //执行Fabric的测试
        runFabricTest(sampleStore); //Runs Fabric tests with constructing channels, joining peers, exercising chaincode
    }
    /**
     * 执行Fabric的测试
     * @param sampleStore
     * @throws Exception
     */
    public void runFabricTest(final SampleStore sampleStore) throws Exception {
        ////////////////////////////
        // Setup client
        //创建HFClient客户的实例
        //Create instance of client.
        HFClient client = HFClient.createNewInstance();
        System.out.println("执行测试用例的时候的HFClient="+client);
        System.out.println("运行测试的时候测试setCryptoSuite="+CryptoSuite.Factory.getCryptoSuite());
        //设置客户的成员适配
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
        ////////////////////////////
        //Construct and run the channels
        //获取到peerOrg1组织
        SampleOrg sampleOrg = testConfig.getIntegrationTestsSampleOrg("peerOrg1");
        //根据条件初始化Channel
        Channel fooChannel = constructChannel(FOO_CHANNEL_NAME, client, sampleOrg);
        System.out.println("这个时候创建的Channel信息为Channel=fooChannel="+fooChannel);
        //把初始化的Channel保存起来sampleStore
        sampleStore.saveChannel(fooChannel);
        System.out.println("初始化foochannel之后的sampleStore="+sampleStore);
        //运行初始化的Channel
        runChannel(client, fooChannel, true, sampleOrg, 0);
        assertFalse(fooChannel.isShutdown());
        fooChannel.shutdown(true); // Force foo channel to shutdown clean up resources.
        assertTrue(fooChannel.isShutdown());
        assertNull(client.getChannel(FOO_CHANNEL_NAME));
        out("\n");
        sampleOrg = testConfig.getIntegrationTestsSampleOrg("peerOrg2");
        //这里是创建bar这个Channel的
        Channel barChannel = constructChannel(BAR_CHANNEL_NAME, client, sampleOrg);
        System.out.println("创建barChannel这个barChannel");
        assertTrue(barChannel.isInitialized());
        /**
         * sampleStore.saveChannel uses {@link Channel#serializeChannel()}
         */
        sampleStore.saveChannel(barChannel);
        assertFalse(barChannel.isShutdown());
        runChannel(client, barChannel, true, sampleOrg, 100); //run a newly constructed bar channel with different b value!
        //let bar channel just shutdown so we have both scenarios.
        out("\nTraverse the blocks for chain %s ", barChannel.getName());
        blockWalker(client, barChannel);
        assertFalse(barChannel.isShutdown());
        assertTrue(barChannel.isInitialized());
        out("That's all folks!");
    }
    /**
     * 将要注册和背书(登记)用户持久化他们到samplestore
     * Will register and enroll users persisting them to samplestore.
     * @param sampleStore
     * @throws Exception
     */
    public void enrollUsersSetup(SampleStore sampleStore) throws Exception {
        ////////////////////////////
        //Set up USERS 建立准备USERS
        //SampleUser can be any implementation that implements org.hyperledger.fabric.sdk.User Interface
        ////////////////////////////
        // get users for all orgs
        out("***** Enrolling Users *****");
        System.out.println("登记Users");
        //循环遍历提供的简单的组织集合,并且设置
        System.out.println("此时testSampleOrgs的大小是testSampleOrgs="+testSampleOrgs.size());
        for (SampleOrg sampleOrg : testSampleOrgs) {
            //获取集合里面每个成员的HFCAClient
            HFCAClient ca = sampleOrg.getCAClient();
            //获取组织的名字
            final String orgName = sampleOrg.getName();
            //获取组织的mspid
            final String mspid = sampleOrg.getMSPID();
            //设置HFCAClient的密码适配
            ca.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
            //判断现在是否运行在TLS模式的下面
            System.out.println("判断当前的模式是否运行在TLS模式下面"+testConfig.isRunningFabricTLS());
            //目前系统没有使用TLS模式因此下面的判断会失败
            if (testConfig.isRunningFabricTLS()) {
                System.out.println("目前运行在TLS模式的下面");
                //This shows how to get a client TLS certificate from Fabric CA
                // we will use one client TLS certificate for orderer peers etc.
                final EnrollmentRequest enrollmentRequestTLS = new EnrollmentRequest();
                enrollmentRequestTLS.addHost("localhost");
                enrollmentRequestTLS.setProfile("tls");
                final Enrollment enroll = ca.enroll("admin", "adminpw", enrollmentRequestTLS);
                final String tlsCertPEM = enroll.getCert();
                final String tlsKeyPEM = getPEMStringFromPrivateKey(enroll.getKey());
                final Properties tlsProperties = new Properties();
                tlsProperties.put("clientKeyBytes", tlsKeyPEM.getBytes(UTF_8));
                tlsProperties.put("clientCertBytes", tlsCertPEM.getBytes(UTF_8));
                clientTLSProperties.put(sampleOrg.getName(), tlsProperties);
                //Save in samplestore for follow on tests.
                sampleStore.storeClientPEMTLCertificate(sampleOrg, tlsCertPEM);
                sampleStore.storeClientPEMTLSKey(sampleOrg, tlsKeyPEM);
            }
            //上面TLS模式下的代码默认不执行的,直接会执行这里的代码
            //获取HFCAClient的信息HFCAInfo
            HFCAInfo info = ca.info(); //just check if we connect at all.
            System.out.println("获取到的HFCAInfo="+info);
            //判断HFCAInfo不是空,是空的话会报错
            assertNotNull(info);
            //此处得到的infoName是ca0
            String infoName = info.getCAName();
            //根据实际的打印效果这个值可能是空的,目前一个值是ca0一个是空
            System.out.println("info.getCAName()获取到的infoName值是="+infoName);
            if (infoName != null && !infoName.isEmpty()) {
                assertEquals(ca.getCAName(), infoName);
            }
            //从sampleStore里面获取简单样例成员SampleUser,根据组织名字orgName,成员的名字是admin
            //在这个测试用例里面由于sampleStore是空的,因此其实这里是创建了一个新的SampleUser
            SampleUser admin = sampleStore.getMember(TEST_ADMIN_NAME, orgName);
            System.out.println("SampleUser成员是admin="+admin);
            System.out.println("admin.isEnrolled()背书情况是="+admin.isEnrolled());
            //如果没有注册背书,那就设置注册背书的属性
            if (!admin.isEnrolled()) {  //Preregistered admin only needs to be enrolled with Fabric caClient.
                System.out.println("开始设置背书人admin.getName()="+admin.getName());
                admin.setEnrollment(ca.enroll(admin.getName(), "adminpw"));
                System.out.println("设置的mspid="+mspid);
                admin.setMspId(mspid);
            }
            //从sampleStore里面获取简单样例成员SampleUser,根据组织名字orgName,user
            SampleUser user = sampleStore.getMember(testUser1, sampleOrg.getName());
            System.out.println("测试用户的成员是user="+user);
            System.out.println("目前的这个用户是否已经注册="+user.isRegistered());
            if (!user.isRegistered()) {  // users need to be registered AND enrolled
                System.out.println("目前没有注册,因此下面开始执行注册的步骤");
                //TODO 目前不知道org1.department1是做什么的
                RegistrationRequest rr = new RegistrationRequest(user.getName(), "org1.department1");
                System.out.println("RegistrationRequest的值是="+rr);
                user.setEnrollmentSecret(ca.register(rr, admin));
            }
            System.out.println("看看user用户是否背书user.isEnrolled()="+user.isEnrolled());
            if (!user.isEnrolled()) {
                user.setEnrollment(ca.enroll(user.getName(), user.getEnrollmentSecret()));
                user.setMspId(mspid);
            }
            //获取组织的名字
            final String sampleOrgName = sampleOrg.getName();
            System.out.println("获取到的final组织的名字是sampleOrgName="+sampleOrgName);
            //获取住址的DomainName领域名字
            final String sampleOrgDomainName = sampleOrg.getDomainName();
            System.out.println("获取到的领域名字是DomainName="+sampleOrgDomainName);
            System.out.println("这里的路径是"+Paths.get(testConfig.getTestChannelPath(),
                    "crypto-config/peerOrganizations/",
                    sampleOrgDomainName, format("/users/Admin@%s/msp/keystore", sampleOrgDomainName)).toFile());
            System.out.println("另外的一个路径是"+Paths.get(testConfig.getTestChannelPath(),
                    "crypto-config/peerOrganizations/", sampleOrgDomainName,
                    format("/users/Admin@%s/msp/signcerts/Admin@%s-cert.pem", sampleOrgDomainName,
                            sampleOrgDomainName)).toFile());
            SampleUser peerOrgAdmin = sampleStore.getMember(sampleOrgName + "Admin", sampleOrgName, sampleOrg.getMSPID(),
                    Util.findFileSk(Paths.get(testConfig.getTestChannelPath(), "crypto-config/peerOrganizations/",
                            sampleOrgDomainName, format("/users/Admin@%s/msp/keystore", sampleOrgDomainName)).toFile()),
                    Paths.get(testConfig.getTestChannelPath(), "crypto-config/peerOrganizations/", sampleOrgDomainName,
                            format("/users/Admin@%s/msp/signcerts/Admin@%s-cert.pem", sampleOrgDomainName, sampleOrgDomainName)).toFile());
            System.out.println("获取到的peerOrgAdmin="+peerOrgAdmin);
            //这里设置一个特殊的Peer节点,类似于admin,这个节点可以创建通道以及加入peers和安装链码
            sampleOrg.setPeerAdmin(peerOrgAdmin); //A special user that can create channels, join peers and install chaincode
            sampleOrg.addUser(user);
            sampleOrg.setAdmin(admin); // The admin of this org --
        }
    }
    static String getPEMStringFromPrivateKey(PrivateKey privateKey) throws IOException {
        StringWriter pemStrWriter = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(pemStrWriter);
        pemWriter.writeObject(privateKey);
        pemWriter.close();
        return pemStrWriter.toString();
    }
    Map<String, Long> expectedMoveRCMap = new HashMap<>(); // map from channel name to move chaincode's return code.
    //CHECKSTYLE.OFF: Method length is 320 lines (max allowed is 150).
    /**
     * 运行初始化的Channel
     * @param client HFClient客户端
     * @param channel 要运行的Channel
     * @param installChaincode 是否需要安装链码
     * @param sampleOrg 组织的信息
     * @param delta 是否延迟
     */
    void runChannel(HFClient client, Channel channel, boolean installChaincode, SampleOrg sampleOrg, int delta) {
        class ChaincodeEventCapture { //A test class to capture chaincode events
            final String handle;
            final BlockEvent blockEvent;
            final ChaincodeEvent chaincodeEvent;
            ChaincodeEventCapture(String handle, BlockEvent blockEvent, ChaincodeEvent chaincodeEvent) {
                this.handle = handle;
                this.blockEvent = blockEvent;
                this.chaincodeEvent = chaincodeEvent;
            }
        }
        // The following is just a test to see if peers and orderers can be added and removed.
        // not pertinent to the code flow.
        //按照官方的注释这个方法其实根本不需要调用
        //testRemovingAddingPeersOrderers(client, channel);
        Vector<ChaincodeEventCapture> chaincodeEvents = new Vector<>(); // Test list to capture chaincode events.
        try {
            //获取channel名字
            final String channelName = channel.getName();
            System.out.println("目前获取到的channelName="+channelName);
            //判断是否是foo这个channel
            boolean isFooChain = FOO_CHANNEL_NAME.equals(channelName);
            out("Running channel %s", channelName);
            System.out.println("正在运行的channelName="+channelName);
            //获取到这个channel的所有排序节点
            Collection<Orderer> orderers = channel.getOrderers();
            //定义一个变量ChaincodeID
            final ChaincodeID chaincodeID;
            //定义教义的响应,这是一个集合
            Collection<ProposalResponse> responses;
            Collection<ProposalResponse> successful = new LinkedList<>();
            Collection<ProposalResponse> failed = new LinkedList<>();
            // Register a chaincode event listener that will trigger for any chaincode id and only for EXPECTED_EVENT_NAME event.
            String chaincodeEventListenerHandle = channel.registerChaincodeEventListener(Pattern.compile(".*"),
                    Pattern.compile(Pattern.quote(EXPECTED_EVENT_NAME)),
                    (handle, blockEvent, chaincodeEvent) -> {
                        chaincodeEvents.add(new ChaincodeEventCapture(handle, blockEvent, chaincodeEvent));
                        String es = blockEvent.getPeer() != null ? blockEvent.getPeer().getName() : blockEvent.getEventHub().getName();
                        out("RECEIVED Chaincode event with handle: %s, chaincode Id: %s, chaincode event name: %s, "
                                        + "transaction id: %s, event payload: \"%s\", from eventhub: %s",
                                handle, chaincodeEvent.getChaincodeId(),
                                chaincodeEvent.getEventName(),
                                chaincodeEvent.getTxId(),
                                new String(chaincodeEvent.getPayload()), es);
                    });
            //For non foo channel unregister event listener to test events are not called.
            //这里判断不是foo这个channel,不是的话不注册事件以及不回调
            if (!isFooChain) {
                System.out.println("isFooChain="+isFooChain);
                channel.unregisterChaincodeEventListener(chaincodeEventListenerHandle);
                chaincodeEventListenerHandle = null;
            }
            ChaincodeID.Builder chaincodeIDBuilder = ChaincodeID.newBuilder().setName(CHAIN_CODE_NAME)
                    .setVersion(CHAIN_CODE_VERSION);
            if (null != CHAIN_CODE_PATH) {
                chaincodeIDBuilder.setPath(CHAIN_CODE_PATH);
            }
            //获取到chaincodeID,这个时候是创建的
            chaincodeID = chaincodeIDBuilder.build();
            System.out.println("创建的chaincodeID="+chaincodeID);
            //如果需要安装链码
            if (installChaincode) {
                ////////////////////////////
                // Install Proposal Request
                //首先安装链码需要设置client的上下文为admin的
                client.setUserContext(sampleOrg.getPeerAdmin());
                out("Creating install proposal");
                System.out.println("正在创建安装链码的协议");
                InstallProposalRequest installProposalRequest = client.newInstallProposalRequest();
                //把上面的chaincodeID设置到InstallProposalRequest里面
                installProposalRequest.setChaincodeID(chaincodeID);
                //如果是foo这个名字的channel
                if (isFooChain) {
                    // on foo chain install from directory.
                    ////For GO language and serving just a single user, chaincodeSource is mostly likely the users GOPATH
                    //设置链码的源码路径 这里的链码是
                    installProposalRequest.setChaincodeSourceLocation(Paths.get(TEST_FIXTURES_PATH, CHAIN_CODE_FILEPATH).toFile());
                    if (testConfig.isFabricVersionAtOrAfter("1.1")) { // Fabric 1.1 added support for  META-INF in the chaincode image.
                        System.out.println("这里是1.1之后的版本这个时候支持 META-INF in the chaincode image");
                        //This sets an index on the variable a in the chaincode // see http://hyperledger-fabric.readthedocs.io/en/master/couchdb_as_state_database.html#using-couchdb-from-chaincode
                        // The file IndexA.json as part of the META-INF will be packaged with the source to create the index.
                        installProposalRequest.setChaincodeMetaInfLocation(new File("src/test/fixture/meta-infs/end2endit"));
                    }
                } else {
                    System.out.println("这里是bar的这个channel");
                    // On bar chain install from an input stream.
                    // For inputstream if indicies are desired the application needs to make sure the META-INF is provided in the stream.
                    // The SDK does not change anything in the stream.
                    if (CHAIN_CODE_LANG.equals(Type.GO_LANG)) {
                        System.out.println("安装bar这个通道,并且是go类型的链码,我找到的链码的路径是"+
                                Paths.get(TEST_FIXTURES_PATH, CHAIN_CODE_FILEPATH, "src", CHAIN_CODE_PATH)+
                                "另外的一个是Paths.get(\"src\", CHAIN_CODE_PATH)="+Paths.get("src", CHAIN_CODE_PATH));
                        installProposalRequest.setChaincodeInputStream(Util.generateTarGzInputStream(
                                (Paths.get(TEST_FIXTURES_PATH, CHAIN_CODE_FILEPATH, "src", CHAIN_CODE_PATH).toFile()),
                                Paths.get("src", CHAIN_CODE_PATH).toString()));
                    } else {
                        installProposalRequest.setChaincodeInputStream(Util.generateTarGzInputStream(
                                (Paths.get(TEST_FIXTURES_PATH, CHAIN_CODE_FILEPATH).toFile()),
                                "src"));
                    }
                }
                installProposalRequest.setChaincodeVersion(CHAIN_CODE_VERSION);
                installProposalRequest.setChaincodeLanguage(CHAIN_CODE_LANG);
                out("Sending install proposal");
                System.out.println("把安装链码的协议发送出去了");
                ////////////////////////////
                // only a client from the same org as the peer can issue an install request
                int numInstallProposal = 0;
                //    Set<String> orgs = orgPeers.keySet();
                //   for (SampleOrg org : testSampleOrgs) {
                Collection<Peer> peers = channel.getPeers();
                numInstallProposal = numInstallProposal + peers.size();
                //这个时候才是真正的发送安装链码的请求到节点上
                responses = client.sendInstallProposal(installProposalRequest, peers);
                for (ProposalResponse response : responses) {
                    if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                        System.out.println("安装链码返回的响应是成功的Txid="+response.getTransactionID()+"peer="+response.getPeer().getName());
                        out("Successful install proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                        successful.add(response);
                    } else {
                        failed.add(response);
                    }
                }
                //   }
                out("Received %d install proposal responses. Successful+verified: %d . Failed: %d", numInstallProposal, successful.size(), failed.size());
                System.out.println("目前收到的安装链码的响应是成功的有="+numInstallProposal+"个,应该成功的有="+ successful.size()+"失败的数量是="+failed.size());
                if (failed.size() > 0) {
                    ProposalResponse first = failed.iterator().next();
                    fail("Not enough endorsers for install :" + successful.size() + ".  " + first.getMessage());
                }
            }
            //   client.setUserContext(sampleOrg.getUser(TEST_ADMIN_NAME));
            //  final ChaincodeID chaincodeID = firstInstallProposalResponse.getChaincodeID();
            // Note installing chaincode does not require transaction no need to
            // send to Orderers
            ///////////////
            //// Instantiate chaincode.
            //安装完链码之后需要实例化链码
            InstantiateProposalRequest instantiateProposalRequest = client.newInstantiationProposalRequest();
            instantiateProposalRequest.setProposalWaitTime(DEPLOYWAITTIME);
            instantiateProposalRequest.setChaincodeID(chaincodeID);
            instantiateProposalRequest.setChaincodeLanguage(CHAIN_CODE_LANG);
            //调用链码的实例化方法
            instantiateProposalRequest.setFcn("init");
            //初始化的时候这里测试了一下链码初始化的时候保存中文后面是否可以取到
//         instantiateProposalRequest.setArgs(new String[] {"a", "我是谁", "b", "" + (200 + delta)});
            instantiateProposalRequest.setArgs(new String[] {"a", "500", "b", "" + (200 + delta)});
            Map<String, byte[]> tm = new HashMap<>();
            tm.put("HyperLedgerFabric", "InstantiateProposalRequest:JavaSDK".getBytes(UTF_8));
            tm.put("method", "InstantiateProposalRequest".getBytes(UTF_8));
            instantiateProposalRequest.setTransientMap(tm);
            /*
              policy OR(Org1MSP.member, Org2MSP.member) meaning 1 signature from someone in either Org1 or Org2
              See README.md Chaincode endorsement policies section for more details.
            */
            //这里是设置背书策略
            ChaincodeEndorsementPolicy chaincodeEndorsementPolicy = new ChaincodeEndorsementPolicy();
            chaincodeEndorsementPolicy.fromYamlFile(new File(TEST_FIXTURES_PATH + "/sdkintegration/chaincodeendorsementpolicy.yaml"));
            System.out.println("背书策略的文件路径是="+TEST_FIXTURES_PATH + "/sdkintegration/chaincodeendorsementpolicy.yaml");
            //设置背书策略
            instantiateProposalRequest.setChaincodeEndorsementPolicy(chaincodeEndorsementPolicy);
            out("Sending instantiateProposalRequest to all peers with arguments: a and b set to 100 and %s respectively", "" + (200 + delta));
            System.out.println("发送实例化链码的请求到所有的peers节点带着参数");
            successful.clear();
            failed.clear();
            if (isFooChain) {  //Send responses both ways with specifying peers and by using those on the channel.
                System.out.println("真正发送实例化链码的请求在foo的这个channel");
                responses = channel.sendInstantiationProposal(instantiateProposalRequest, channel.getPeers());
            } else {
                responses = channel.sendInstantiationProposal(instantiateProposalRequest);
            }
            for (ProposalResponse response : responses) {
                if (response.isVerified() && response.getStatus() == ProposalResponse.Status.SUCCESS) {
                    successful.add(response);
                    out("Succesful instantiate proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                    System.out.println("实例化链码成功了");
                } else {
                    failed.add(response);
                }
            }
            out("Received %d instantiate proposal responses. Successful+verified: %d . Failed: %d", responses.size(), successful.size(), failed.size());
            if (failed.size() > 0) {
                for (ProposalResponse fail : failed) {
                    out("Not enough endorsers for instantiate :" + successful.size() + "endorser failed with " + fail.getMessage() + ", on peer" + fail.getPeer());
                }
                ProposalResponse first = failed.iterator().next();
                fail("Not enough endorsers for instantiate :" + successful.size() + "endorser failed with " + first.getMessage() + ". Was verified:" + first.isVerified());
            }
            ///////////////
            /// Send instantiate transaction to orderer
            out("Sending instantiateTransaction to orderer with a and b set to 100 and %s respectively", "" + (200 + delta));
            System.out.println("发送实例化链码交易到背书节点");
            //Specify what events should complete the interest in this transaction. This is the default
            // for all to complete. It's possible to specify many different combinations like
            //any from a group, all from one group and just one from another or even None(NOfEvents.createNoEvents).
            // See. Channel.NOfEvents
            Channel.NOfEvents nOfEvents = createNofEvents();
            if (!channel.getPeers(EnumSet.of(PeerRole.EVENT_SOURCE)).isEmpty()) {
                nOfEvents.addPeers(channel.getPeers(EnumSet.of(PeerRole.EVENT_SOURCE)));
            }
            if (!channel.getEventHubs().isEmpty()) {
                nOfEvents.addEventHubs(channel.getEventHubs());
            }
            channel.sendTransaction(successful, createTransactionOptions() //Basically the default options but shows it's usage.
                    .userContext(client.getUserContext()) //could be a different user context. this is the default.
                    .shuffleOrders(false) // don't shuffle any orderers the default is true.
                    .orderers(channel.getOrderers()) // specify the orderers we want to try this transaction. Fails once all Orderers are tried.
                    .nOfEvents(nOfEvents) // The events to signal the completion of the interest in the transaction
            ).thenApply(transactionEvent -> {
                waitOnFabric(0);
                assertTrue(transactionEvent.isValid()); // must be valid to be here.
                System.out.println("交易事务必须是有效的="+transactionEvent.isValid());
                assertNotNull(transactionEvent.getSignature()); //musth have a signature.
                System.out.println("交易事务必须有签名="+transactionEvent.getSignature());
                BlockEvent blockEvent = transactionEvent.getBlockEvent(); // This is the blockevent that has this transaction.
                assertNotNull(blockEvent.getBlock()); // Make sure the RAW Fabric block is returned.
                out("Finished instantiate transaction with transaction id %s", transactionEvent.getTransactionID());
                try {
                    assertEquals(blockEvent.getChannelId(), channel.getName());
                    successful.clear();
                    failed.clear();
                    //把client的上下文设置为user1
                    client.setUserContext(sampleOrg.getUser(testUser1));
                    System.out.println("上下文设置为user1的时候sampleOrg="+sampleOrg);
                    System.out.println("上下文设置为user1之后的client="+client);
                    ///////////////
                    /// Send transaction proposal to all peers
                    //发送交易事务到所有的peers节点
                    TransactionProposalRequest transactionProposalRequest = client.newTransactionProposalRequest();
                    transactionProposalRequest.setChaincodeID(chaincodeID);
                    transactionProposalRequest.setChaincodeLanguage(CHAIN_CODE_LANG);
                    //transactionProposalRequest.setFcn("invoke");
                    transactionProposalRequest.setFcn("move");
                    transactionProposalRequest.setProposalWaitTime(testConfig.getProposalWaitTime());
                    transactionProposalRequest.setArgs("a", "b", "100");
                    Map<String, byte[]> tm2 = new HashMap<>();
                    tm2.put("HyperLedgerFabric", "TransactionProposalRequest:JavaSDK".getBytes(UTF_8)); //Just some extra junk in transient map
                    tm2.put("method", "TransactionProposalRequest".getBytes(UTF_8)); // ditto
                    tm2.put("result", ":)".getBytes(UTF_8));  // This should be returned in the payload see chaincode why.
                    //如果链码的语言是GO语言并且Fabric的版本大于1.2
                    if (Type.GO_LANG.equals(CHAIN_CODE_LANG) && testConfig.isFabricVersionAtOrAfter("1.2")) {
                        System.out.println("目前的链码是go语言版本的并且客户端的版本大于1.2");
                        expectedMoveRCMap.put(channelName, random.nextInt(300) + 100L); // the chaincode will return this as status see chaincode why.
                        tm2.put("rc", (expectedMoveRCMap.get(channelName) + "").getBytes(UTF_8));  // This should be returned see chaincode why.
                        // 400 and above results in the peer not endorsing!
                    } else {
                        expectedMoveRCMap.put(channelName, 200L); // not really supported for Java or Node.
                    }
                    tm2.put(EXPECTED_EVENT_NAME, EXPECTED_EVENT_DATA);  //This should trigger an event see chaincode why.
                    transactionProposalRequest.setTransientMap(tm2);
                    out("sending transactionProposal to all peers with arguments: move(a,b,100)");
                    //  Collection<ProposalResponse> transactionPropResp = channel.sendTransactionProposalToEndorsers(transactionProposalRequest);
                    Collection<ProposalResponse> transactionPropResp = channel.sendTransactionProposal(transactionProposalRequest, channel.getPeers());
                    for (ProposalResponse response : transactionPropResp) {
                        if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                            out("Successful transaction proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                            successful.add(response);
                        } else {
                            failed.add(response);
                        }
                    }
                    out("Received %d transaction proposal responses. Successful+verified: %d . Failed: %d",
                            transactionPropResp.size(), successful.size(), failed.size());
                    if (failed.size() > 0) {
                        ProposalResponse firstTransactionProposalResponse = failed.iterator().next();
                        fail("Not enough endorsers for invoke(move a,b,100):" + failed.size() + " endorser error: " +
                                firstTransactionProposalResponse.getMessage() +
                                ". Was verified: " + firstTransactionProposalResponse.isVerified());
                    }
                    // Check that all the proposals are consistent with each other. We should have only one set
                    // where all the proposals above are consistent. Note the when sending to Orderer this is done automatically.
                    //  Shown here as an example that applications can invoke and select.
                    // See org.hyperledger.fabric.sdk.proposal.consistency_validation config property.
                    Collection<Set<ProposalResponse>> proposalConsistencySets = SDKUtils.getProposalConsistencySets(transactionPropResp);
                    if (proposalConsistencySets.size() != 1) {
                        fail(format("Expected only one set of consistent proposal responses but got %d", proposalConsistencySets.size()));
                    }
                    out("Successfully received transaction proposal responses.");
                    //  System.exit(10);
                    ProposalResponse resp = successful.iterator().next();
                    byte[] x = resp.getChaincodeActionResponsePayload(); // This is the data returned by the chaincode.
                    String resultAsString = null;
                    if (x != null) {
                        resultAsString = new String(x, UTF_8);
                    }
                    assertEquals(":)", resultAsString);
                    assertEquals(expectedMoveRCMap.get(channelName).longValue(), resp.getChaincodeActionResponseStatus()); //Chaincode's status.
                    TxReadWriteSetInfo readWriteSetInfo = resp.getChaincodeActionResponseReadWriteSetInfo();
                    //See blockwalker below how to transverse this
                    assertNotNull(readWriteSetInfo);
                    assertTrue(readWriteSetInfo.getNsRwsetCount() > 0);
                    ChaincodeID cid = resp.getChaincodeID();
                    assertNotNull(cid);
                    final String path = cid.getPath();
                    if (null == CHAIN_CODE_PATH) {
                        assertTrue(path == null || "".equals(path));
                    } else {
                        assertEquals(CHAIN_CODE_PATH, path);
                    }
                    assertEquals(CHAIN_CODE_NAME, cid.getName());
                    assertEquals(CHAIN_CODE_VERSION, cid.getVersion());
                    ////////////////////////////
                    // Send Transaction Transaction to orderer
                    out("Sending chaincode transaction(move a,b,100) to orderer.");
                    return channel.sendTransaction(successful).get(testConfig.getTransactionWaitTime(), TimeUnit.SECONDS);
                } catch (Exception e) {
                    out("Caught an exception while invoking chaincode");
                    e.printStackTrace();
                    fail("Failed invoking chaincode with error : " + e.getMessage());
                }
                return null;
            }).thenApply(transactionEvent -> {
                try {
                    waitOnFabric(0);
                    assertTrue(transactionEvent.isValid()); // must be valid to be here.
                    out("Finished transaction with transaction id %s", transactionEvent.getTransactionID());
                    testTxID = transactionEvent.getTransactionID(); // used in the channel queries later
                    ////////////////////////////
                    // Send Query Proposal to all peers
                    //
                    String expect = "" + (300 + delta);
                    out("Now query chaincode for the value of b.");
                    QueryByChaincodeRequest queryByChaincodeRequest = client.newQueryProposalRequest();
                    queryByChaincodeRequest.setArgs(new String[] {"b"});
                    //对于Java链码，我a存储的是汉字因此查询的是a
                    queryByChaincodeRequest.setFcn("query");
                    queryByChaincodeRequest.setChaincodeID(chaincodeID);
                    Map<String, byte[]> tm2 = new HashMap<>();
                    tm2.put("HyperLedgerFabric", "QueryByChaincodeRequest:JavaSDK".getBytes(UTF_8));
                    tm2.put("method", "QueryByChaincodeRequest".getBytes(UTF_8));
                    queryByChaincodeRequest.setTransientMap(tm2);
                    Collection<ProposalResponse> queryProposals = channel.queryByChaincode(queryByChaincodeRequest, channel.getPeers());
                    for (ProposalResponse proposalResponse : queryProposals) {
                        if (!proposalResponse.isVerified() || proposalResponse.getStatus() != ProposalResponse.Status.SUCCESS) {
                            fail("Failed query proposal from peer " + proposalResponse.getPeer().getName() + " status: " + proposalResponse.getStatus() +
                                    ". Messages: " + proposalResponse.getMessage()
                                    + ". Was verified : " + proposalResponse.isVerified());
                        } else {
                            String payload = proposalResponse.getProposalResponse().getResponse().getPayload().toStringUtf8();
                            System.out.println("返回来的数据是payload="+payload);
                            out("Query payload of b from peer %s returned %s", proposalResponse.getPeer().getName(), payload);
                            assertEquals(payload, expect);
                        }
                    }
                    return null;
                } catch (Exception e) {
                    out("Caught exception while running query");
                    e.printStackTrace();
                    fail("Failed during chaincode query with error : " + e.getMessage());
                }
                return null;
            }).exceptionally(e -> {
                if (e instanceof TransactionEventException) {
                    BlockEvent.TransactionEvent te = ((TransactionEventException) e).getTransactionEvent();
                    if (te != null) {
                        throw new AssertionError(format("Transaction with txid %s failed. %s", te.getTransactionID(), e.getMessage()), e);
                    }
                }

                throw new AssertionError(format("Test failed with %s exception %s", e.getClass().getName(), e.getMessage()), e);

            }).get(testConfig.getTransactionWaitTime(), TimeUnit.SECONDS);
            // Channel queries
            // We can only send channel queries to peers that are in the same org as the SDK user context
            // Get the peers from the current org being used and pick one randomly to send the queries to.
            //  Set<Peer> peerSet = sampleOrg.getPeers();
            //  Peer queryPeer = peerSet.iterator().next();
            //   out("Using peer %s for channel queries", queryPeer.getName());
            BlockchainInfo channelInfo = channel.queryBlockchainInfo();
            out("Channel info for : " + channelName);
            out("Channel height: " + channelInfo.getHeight());
            String chainCurrentHash = Hex.encodeHexString(channelInfo.getCurrentBlockHash());
            String chainPreviousHash = Hex.encodeHexString(channelInfo.getPreviousBlockHash());
            out("Chain current block hash: " + chainCurrentHash);
            out("Chainl previous block hash: " + chainPreviousHash);
            // Query by block number. Should return latest block, i.e. block number 2
            BlockInfo returnedBlock = channel.queryBlockByNumber(channelInfo.getHeight() - 1);
            String previousHash = Hex.encodeHexString(returnedBlock.getPreviousHash());
            out("queryBlockByNumber returned correct block with blockNumber " + returnedBlock.getBlockNumber()
                    + " \n previous_hash " + previousHash);
            assertEquals(channelInfo.getHeight() - 1, returnedBlock.getBlockNumber());
            assertEquals(chainPreviousHash, previousHash);
            // Query by block hash. Using latest block's previous hash so should return block number 1
            byte[] hashQuery = returnedBlock.getPreviousHash();
            returnedBlock = channel.queryBlockByHash(hashQuery);
            out("queryBlockByHash returned block with blockNumber " + returnedBlock.getBlockNumber());
            assertEquals(channelInfo.getHeight() - 2, returnedBlock.getBlockNumber());
            // Query block by TxID. Since it's the last TxID, should be block 2
            returnedBlock = channel.queryBlockByTransactionID(testTxID);
            out("queryBlockByTxID returned block with blockNumber " + returnedBlock.getBlockNumber());
            assertEquals(channelInfo.getHeight() - 1, returnedBlock.getBlockNumber());
            // query transaction by ID
            TransactionInfo txInfo = channel.queryTransactionByID(testTxID);
            out("QueryTransactionByID returned TransactionInfo: txID " + txInfo.getTransactionID()
                    + "\n     validation code " + txInfo.getValidationCode().getNumber());
            if (chaincodeEventListenerHandle != null) {
                channel.unregisterChaincodeEventListener(chaincodeEventListenerHandle);
                //Should be two. One event in chaincode and two notification for each of the two event hubs

                final int numberEventsExpected = channel.getEventHubs().size() +
                        channel.getPeers(EnumSet.of(PeerRole.EVENT_SOURCE)).size();
                //just make sure we get the notifications.
                for (int i = 15; i > 0; --i) {
                    if (chaincodeEvents.size() == numberEventsExpected) {
                        break;
                    } else {
                        Thread.sleep(90); // wait for the events.
                    }
                }
                assertEquals(numberEventsExpected, chaincodeEvents.size());
                for (ChaincodeEventCapture chaincodeEventCapture : chaincodeEvents) {
                    assertEquals(chaincodeEventListenerHandle, chaincodeEventCapture.handle);
                    assertEquals(testTxID, chaincodeEventCapture.chaincodeEvent.getTxId());
                    assertEquals(EXPECTED_EVENT_NAME, chaincodeEventCapture.chaincodeEvent.getEventName());
                    assertTrue(Arrays.equals(EXPECTED_EVENT_DATA, chaincodeEventCapture.chaincodeEvent.getPayload()));
                    assertEquals(CHAIN_CODE_NAME, chaincodeEventCapture.chaincodeEvent.getChaincodeId());
                    BlockEvent blockEvent = chaincodeEventCapture.blockEvent;
                    assertEquals(channelName, blockEvent.getChannelId());
                    //   assertTrue(channel.getEventHubs().contains(blockEvent.getEventHub()));
                }
            } else {
                assertTrue(chaincodeEvents.isEmpty());
            }
            out("Running for Channel %s done", channelName);
        } catch (Exception e) {
            out("Caught an exception running channel %s", channel.getName());
            e.printStackTrace();
            fail("Test failed with error : " + e.getMessage());
        }
    }
    /**
     * 创建Channel的方法
     * @param name Channel的名字
     * @param client HFClient实例
     * @param sampleOrg 组织的名字
     * @return
     * @throws Exception
     */
    Channel constructChannel(String name, HFClient client, SampleOrg sampleOrg) throws Exception {
        ////////////////////////////
        //Construct the channel
        out("Constructing channel %s", name);
        System.out.println("目前正在创建channel="+name);
        //boolean doPeerEventing = false;
        boolean doPeerEventing = !testConfig.isRunningAgainstFabric10() && BAR_CHANNEL_NAME.equals(name);
        System.out.println("doPeerEventing="+doPeerEventing);
//     boolean doPeerEventing = !testConfig.isRunningAgainstFabric10() && FOO_CHANNEL_NAME.equals(name);
        //Only peer Admin org
        //获取到peerAdmin节点 用户成员
        SampleUser peerAdmin = sampleOrg.getPeerAdmin();
        //把目前的HFClient客户端上下文设置为peerAdmin
        client.setUserContext(peerAdmin);
        //定义一个集合存储排序节点
        Collection<Orderer> orderers = new LinkedList<>();
        for (String orderName : sampleOrg.getOrdererNames()) {
            System.out.println("获取到所有的组织名字orderName="+orderName);
            Properties ordererProperties = testConfig.getOrdererProperties(orderName);
            for (String key : ordererProperties.stringPropertyNames()) {
                System.out.println("获取到ordererProperties="+key + "=" + ordererProperties.getProperty(key));
            }
            //example of setting keepAlive to avoid timeouts on inactive http2 connections.
            // Under 5 minutes would require changes to server side to accept faster ping rates.
            ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveTime", new Object[] {5L, TimeUnit.MINUTES});
            ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveTimeout", new Object[] {8L, TimeUnit.SECONDS});
            ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveWithoutCalls", new Object[] {true});
            for (String key : ordererProperties.stringPropertyNames()) {
                System.out.println("再次设置属性之后获取到ordererProperties="+key + "=" + ordererProperties.getProperty(key));
            }
            //创建排序节点并把排序节点添加到集合
            orderers.add(client.newOrderer(orderName, sampleOrg.getOrdererLocation(orderName), ordererProperties));
        }
        //Just pick the first orderer in the list to create the channel.
        //获取到第一个排序节点Orderer
        Orderer anOrderer = orderers.iterator().next();
        System.out.println("获取到的一个排序节点Orderer是"+anOrderer);
        //从集合里面踢出刚才获取的排序节点Orderer
        orderers.remove(anOrderer);
        String path = TEST_FIXTURES_PATH + "/sdkintegration/e2e-2Orgs/" + testConfig.getFabricConfigGenVers() + "/" + name + ".tx";
        System.out.println("channel的文件路径是path="+path);
        //根据channel的配置文件创建ChannelConfiguration
        ChannelConfiguration channelConfiguration = new ChannelConfiguration(new File(path));
        //Create channel that has only one signer that is this orgs peer admin.
        //If channel creation policy needed more signature they would need to be added too.
        Channel newChannel = client.newChannel(name, anOrderer, channelConfiguration,
                client.getChannelConfigurationSignature(channelConfiguration, peerAdmin));
        out("Created channel %s", name);
        System.out.println("Channel创建成功了,Channel的名字是="+name);
        System.out.println("Channel创建成功了,Channel="+newChannel);
        boolean everyother = true; //test with both cases when doing peer eventing.
        for (String peerName : sampleOrg.getPeerNames()) {
            System.out.println("创建通道的时候获取到的每一个Peer的名字peerName="+peerName);
            String peerLocation = sampleOrg.getPeerLocation(peerName);
            System.out.println("创建通道的时候获取到的peerLocation="+peerLocation);
            Properties peerProperties = testConfig.getPeerProperties(peerName); //test properties for peer.. if any.
            for (String key : peerProperties.stringPropertyNames()) {
                System.out.println("获取到peerProperties="+key + "=" + peerProperties.getProperty(key));
            }
            if (peerProperties == null) {
                System.out.println("获取到的peerProperties是空的");
                peerProperties = new Properties();
            }
            //Example of setting specific options on grpc's NettyChannelBuilder
            peerProperties.put("grpc.NettyChannelBuilderOption.maxInboundMessageSize", 9000000);
            //创建新的Peer节点
            Peer peer = client.newPeer(peerName, peerLocation, peerProperties);
            if (testConfig.isFabricVersionAtOrAfter("1.3")) {
                System.out.println("创建新的Peer节点之后和1.3版本的关系满足条件");
                newChannel.joinPeer(peer, createPeerOptions().setPeerRoles(EnumSet.of(PeerRole.ENDORSING_PEER, PeerRole.LEDGER_QUERY, PeerRole.CHAINCODE_QUERY, PeerRole.EVENT_SOURCE))); //Default is all roles.
            } else {
                System.out.println("创建新的Peer节点不满足1.3的条件");
                if (doPeerEventing && everyother) {
                    System.out.println("满足条件doPeerEventing && everyother");
                    newChannel.joinPeer(peer, createPeerOptions().setPeerRoles(EnumSet.of(PeerRole.ENDORSING_PEER, PeerRole.LEDGER_QUERY, PeerRole.CHAINCODE_QUERY, PeerRole.EVENT_SOURCE))); //Default is all roles.
                } else {
                    System.out.println("不满足条件doPeerEventing && everyother");
                    // Set peer to not be all roles but eventing.
                    newChannel.joinPeer(peer, createPeerOptions().setPeerRoles(EnumSet.of(PeerRole.ENDORSING_PEER, PeerRole.LEDGER_QUERY, PeerRole.CHAINCODE_QUERY)));
                }
            }
            out("Peer %s joined channel %s", peerName, name);
            System.out.println("Peer节点加入channel了channel="+name+"peerName="+peerName);
            everyother = !everyother;
        }
        //just for testing ...
        if (doPeerEventing || testConfig.isFabricVersionAtOrAfter("1.3")) {
            System.out.println("doPeerEventing || testConfig.isFabricVersionAtOrAfter(\"1.3\")是满足的");
            // Make sure there is one of each type peer at the very least.
            //确保每一个通道里面至少有1个peer
            assertFalse(newChannel.getPeers(EnumSet.of(PeerRole.EVENT_SOURCE)).isEmpty());
            assertFalse(newChannel.getPeers(PeerRole.NO_EVENT_SOURCE).isEmpty());
        }
        for (Orderer orderer : orderers) { //add remaining orderers if any.
            //把遍历到的每一个排序节点加入newChannel
            newChannel.addOrderer(orderer);
        }
        //目前不知道EventHub是什么意思,貌似是事件回调
        for (String eventHubName : sampleOrg.getEventHubNames()) {
            System.out.println("循环遍历出每一个eventHubName="+eventHubName);
            final Properties eventHubProperties = testConfig.getEventHubProperties(eventHubName);
            eventHubProperties.put("grpc.NettyChannelBuilderOption.keepAliveTime", new Object[] {5L, TimeUnit.MINUTES});
            eventHubProperties.put("grpc.NettyChannelBuilderOption.keepAliveTimeout", new Object[] {8L, TimeUnit.SECONDS});
            EventHub eventHub = client.newEventHub(eventHubName, sampleOrg.getEventHubLocation(eventHubName),
                    eventHubProperties);
            newChannel.addEventHub(eventHub);
        }
        newChannel.initialize();
        out("Finished initialization channel %s", name);
        System.out.println("newChannel初始化成功"+name);
        //Just checks if channel can be serialized and deserialized .. otherwise this is just a waste :)
        byte[] serializedChannelBytes = newChannel.serializeChannel();
        newChannel.shutdown(true);
        return client.deSerializeChannel(serializedChannelBytes).initialize();
    }
    private void waitOnFabric(int additional) {
        //NOOP today
    }
    void blockWalker(HFClient client, Channel channel) throws InvalidArgumentException, ProposalException, IOException {
        try {
            BlockchainInfo channelInfo = channel.queryBlockchainInfo();
            for (long current = channelInfo.getHeight() - 1; current > -1; --current) {
                BlockInfo returnedBlock = channel.queryBlockByNumber(current);
                final long blockNumber = returnedBlock.getBlockNumber();
                out("current block number %d has data hash: %s", blockNumber, Hex.encodeHexString(returnedBlock.getDataHash()));
                out("current block number %d has previous hash id: %s", blockNumber, Hex.encodeHexString(returnedBlock.getPreviousHash()));
                out("current block number %d has calculated block hash is %s", blockNumber, Hex.encodeHexString(SDKUtils.calculateBlockHash(client,
                        blockNumber, returnedBlock.getPreviousHash(), returnedBlock.getDataHash())));
                final int envelopeCount = returnedBlock.getEnvelopeCount();
                assertEquals(1, envelopeCount);
                out("current block number %d has %d envelope count:", blockNumber, returnedBlock.getEnvelopeCount());
                int i = 0;
                int transactionCount = 0;
                for (BlockInfo.EnvelopeInfo envelopeInfo : returnedBlock.getEnvelopeInfos()) {
                    ++i;
                    out("  Transaction number %d has transaction id: %s", i, envelopeInfo.getTransactionID());
                    final String channelId = envelopeInfo.getChannelId();
                    assertTrue("foo".equals(channelId) || "bar".equals(channelId));
                    out("  Transaction number %d has channel id: %s", i, channelId);
                    out("  Transaction number %d has epoch: %d", i, envelopeInfo.getEpoch());
                    out("  Transaction number %d has transaction timestamp: %tB %<te,  %<tY  %<tT %<Tp", i, envelopeInfo.getTimestamp());
                    out("  Transaction number %d has type id: %s", i, "" + envelopeInfo.getType());
                    out("  Transaction number %d has nonce : %s", i, "" + Hex.encodeHexString(envelopeInfo.getNonce()));
                    out("  Transaction number %d has submitter mspid: %s,  certificate: %s", i, envelopeInfo.getCreator().getMspid(), envelopeInfo.getCreator().getId());
                    if (envelopeInfo.getType() == TRANSACTION_ENVELOPE) {
                        ++transactionCount;
                        BlockInfo.TransactionEnvelopeInfo transactionEnvelopeInfo = (BlockInfo.TransactionEnvelopeInfo) envelopeInfo;
                        out("  Transaction number %d has %d actions", i, transactionEnvelopeInfo.getTransactionActionInfoCount());
                        assertEquals(1, transactionEnvelopeInfo.getTransactionActionInfoCount()); // for now there is only 1 action per transaction.
                        out("  Transaction number %d isValid %b", i, transactionEnvelopeInfo.isValid());
                        assertEquals(transactionEnvelopeInfo.isValid(), true);
                        out("  Transaction number %d validation code %d", i, transactionEnvelopeInfo.getValidationCode());
                        assertEquals(0, transactionEnvelopeInfo.getValidationCode());
                        int j = 0;
                        for (BlockInfo.TransactionEnvelopeInfo.TransactionActionInfo transactionActionInfo : transactionEnvelopeInfo.getTransactionActionInfos()) {
                            ++j;
                            out("   Transaction action %d has response status %d", j, transactionActionInfo.getResponseStatus());
                            long excpectedStatus = current == 2 && i == 1 && j == 1 ? expectedMoveRCMap.get(channel.getName()) : 200; // only transaction we changed the status code.
                            assertEquals(format("channel %s current: %d, i: %d.  transaction action j=%d", channel.getName(), current, i, j), excpectedStatus, transactionActionInfo.getResponseStatus());
                            out("   Transaction action %d has response message bytes as string: %s", j,
                                    printableString(new String(transactionActionInfo.getResponseMessageBytes(), UTF_8)));
                            out("   Transaction action %d has %d endorsements", j, transactionActionInfo.getEndorsementsCount());
                            assertEquals(2, transactionActionInfo.getEndorsementsCount());
                            for (int n = 0; n < transactionActionInfo.getEndorsementsCount(); ++n) {
                                BlockInfo.EndorserInfo endorserInfo = transactionActionInfo.getEndorsementInfo(n);
                                out("Endorser %d signature: %s", n, Hex.encodeHexString(endorserInfo.getSignature()));
                                out("Endorser %d endorser: mspid %s \n certificate %s", n, endorserInfo.getMspid(), endorserInfo.getId());
                            }
                            out("   Transaction action %d has %d chaincode input arguments", j, transactionActionInfo.getChaincodeInputArgsCount());
                            for (int z = 0; z < transactionActionInfo.getChaincodeInputArgsCount(); ++z) {
                                out("     Transaction action %d has chaincode input argument %d is: %s", j, z,
                                        printableString(new String(transactionActionInfo.getChaincodeInputArgs(z), UTF_8)));
                            }
                            out("   Transaction action %d proposal response status: %d", j,
                                    transactionActionInfo.getProposalResponseStatus());
                            out("   Transaction action %d proposal response payload: %s", j,
                                    printableString(new String(transactionActionInfo.getProposalResponsePayload())));
                            String chaincodeIDName = transactionActionInfo.getChaincodeIDName();
                            String chaincodeIDVersion = transactionActionInfo.getChaincodeIDVersion();
                            String chaincodeIDPath = transactionActionInfo.getChaincodeIDPath();
                            out("   Transaction action %d proposal chaincodeIDName: %s, chaincodeIDVersion: %s,  chaincodeIDPath: %s ", j,
                                    chaincodeIDName, chaincodeIDVersion, chaincodeIDPath);
                            // Check to see if we have our expected event.
                            if (blockNumber == 2) {
                                ChaincodeEvent chaincodeEvent = transactionActionInfo.getEvent();
                                assertNotNull(chaincodeEvent);
                                assertTrue(Arrays.equals(EXPECTED_EVENT_DATA, chaincodeEvent.getPayload()));
                                assertEquals(testTxID, chaincodeEvent.getTxId());
                                assertEquals(CHAIN_CODE_NAME, chaincodeEvent.getChaincodeId());
                                assertEquals(EXPECTED_EVENT_NAME, chaincodeEvent.getEventName());
                                assertEquals(CHAIN_CODE_NAME, chaincodeIDName);
                                assertEquals("github.com/example_cc", chaincodeIDPath);
                                assertEquals("1", chaincodeIDVersion);
                            }
                            TxReadWriteSetInfo rwsetInfo = transactionActionInfo.getTxReadWriteSet();
                            if (null != rwsetInfo) {
                                out("   Transaction action %d has %d name space read write sets", j, rwsetInfo.getNsRwsetCount());
                                for (TxReadWriteSetInfo.NsRwsetInfo nsRwsetInfo : rwsetInfo.getNsRwsetInfos()) {
                                    final String namespace = nsRwsetInfo.getNamespace();
                                    KvRwset.KVRWSet rws = nsRwsetInfo.getRwset();
                                    int rs = -1;
                                    for (KvRwset.KVRead readList : rws.getReadsList()) {
                                        rs++;
                                        out("     Namespace %s read set %d key %s  version [%d:%d]", namespace, rs, readList.getKey(),
                                                readList.getVersion().getBlockNum(), readList.getVersion().getTxNum());
                                        if ("bar".equals(channelId) && blockNumber == 2) {
                                            if ("example_cc_go".equals(namespace)) {
                                                if (rs == 0) {
                                                    assertEquals("a", readList.getKey());
                                                    assertEquals(1, readList.getVersion().getBlockNum());
                                                    assertEquals(0, readList.getVersion().getTxNum());
                                                } else if (rs == 1) {
                                                    assertEquals("b", readList.getKey());
                                                    assertEquals(1, readList.getVersion().getBlockNum());
                                                    assertEquals(0, readList.getVersion().getTxNum());
                                                } else {
                                                    fail(format("unexpected readset %d", rs));
                                                }
                                                TX_EXPECTED.remove("readset1");
                                            }
                                        }
                                    }
                                    rs = -1;
                                    for (KvRwset.KVWrite writeList : rws.getWritesList()) {
                                        rs++;
                                        String valAsString = printableString(new String(writeList.getValue().toByteArray(), UTF_8));
                                        out("     Namespace %s write set %d key %s has value '%s' ", namespace, rs,
                                                writeList.getKey(),
                                                valAsString);
                                        if ("bar".equals(channelId) && blockNumber == 2) {
                                            if (rs == 0) {
                                                assertEquals("a", writeList.getKey());
                                                assertEquals("400", valAsString);
                                            } else if (rs == 1) {
                                                assertEquals("b", writeList.getKey());
                                                assertEquals("400", valAsString);
                                            } else {
                                                fail(format("unexpected writeset %d", rs));
                                            }
                                            TX_EXPECTED.remove("writeset1");
                                        }
                                    }
                                }
                            }
                        }
                    }
                    assertEquals(transactionCount, returnedBlock.getTransactionCount());
                }
            }
            if (!TX_EXPECTED.isEmpty()) {
                fail(TX_EXPECTED.get(0));
            }
        } catch (InvalidProtocolBufferRuntimeException e) {
            throw e.getCause();
        }
    }
}
