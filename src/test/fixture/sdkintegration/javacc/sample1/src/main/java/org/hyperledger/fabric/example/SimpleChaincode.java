package org.hyperledger.fabric.example;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.google.gson.Gson;
import com.google.protobuf.ByteString;
import io.netty.handler.ssl.OpenSsl;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.shim.ChaincodeBase;
import org.hyperledger.fabric.shim.ChaincodeStub;
import static java.nio.charset.StandardCharsets.UTF_8;
public class SimpleChaincode extends ChaincodeBase {
    private static Log _logger = LogFactory.getLog(SimpleChaincode.class);
    //用户1的公钥
    private  static  String  publicKey1="";
    //用户2的公钥
    private  static  String publicKey2="";
    /**
     * 链码初始化的方法,初始化的时候保存用户的公钥
     * @param stub
     * @return
     */
    @Override
    public Response init(ChaincodeStub stub) {
        try {
            _logger.info("Init java simple chaincode");
            String func = stub.getFunction();
            if (!func.equals("init")) {
                return newErrorResponse("function other than init is not supported");
            }
            List<String> args = stub.getParameters();
            if (args.size() != 4) {
                newErrorResponse("Incorrect number of arguments. Expecting 4");
            }
            // Initialize the chaincode
            //取出第一个参数,第一个参数是用户1的公钥
            publicKey1 = args.get(0);
            //第二个参数是用户2的公钥
            publicKey2 = args.get(1);
            if(publicKey1==null||"".equals(publicKey1)){
                newErrorResponse("can shu 1 bu neng wei kong ");
            }
            if(publicKey2==null||"".equals(publicKey2)){
                newErrorResponse("can shu 2 bu neng wei kong ");
            }
            //取出第二个参数,这个参数是第一个参数的值,第一个参数是key
            // int account1Value = Integer.parseInt(args.get(1));
            //取出第三个参数,是第二个key
//            String account2Key = args.get(2);
//            int account2Value = Integer.parseInt(args.get(3));
//            Gson Gson=new Gson();
//            Map map=new HashMap();
//            map.put("name","zhangsan");
//            map.put("name1","zhangsan");
//            byte[] creator = stub.getCreator();
//            System.out.println("打印到的证书="+new String(creator,"UTF-8"));
//            _logger.info(String.format("account %s, value = %s; account %s, value %s", account1Key, args.get(1), account2Key, account2Value));
//            stub.putStringState(account1Key, Gson.toJson(map));
//            stub.putStringState(account2Key, args.get(3));
            return newSuccessResponse();
        } catch (Throwable e) {
            return newErrorResponse(e);
        }
    }
    @Override
    public Response invoke(ChaincodeStub stub) {
        try {
            _logger.info("Invoke java simple chaincode");
            String func = stub.getFunction();
            List<String> params = stub.getParameters();
            if (func.equals("move")) {
                return move(stub, params);
            }
            if (func.equals("delete")) {
                return delete(stub, params);
            }
            if (func.equals("query")) {
                return query(stub, params);
            }
            return newErrorResponse("Invalid invoke function name. Expecting one of: [\"move\", \"delete\", \"query\"]");
        } catch (Throwable e) {
            return newErrorResponse(e);
        }
    }
    private Response move(ChaincodeStub stub, List<String> args) throws UnsupportedEncodingException {
        if (args.size() != 3) {
            return newErrorResponse("Incorrect number of arguments. Expecting 3");
        }
        //第一个参数代表key值,要存储的
        String accountFromKey = args.get(0);
        //第二个参数代表随机数
        String accountRanndom = args.get(1);
        //第三个参数代表要加密的值value
        String accountValue = args.get(2);
        //第四个参数代表时间戳
        String accountTimeStamp = args.get(3);
        Gson gson=new Gson();
        Map map=new HashMap();
        //TODO 这里的accountValue要使用公钥计算出来
        map.put(accountFromKey,accountValue);
        stub.putStringState(accountFromKey, gson.toJson(map));
        _logger.info("Transfer complete");
        Map<String, byte[]> transientMap = stub.getTransient();
        if (null != transientMap) {
            if (transientMap.containsKey("event") && transientMap.get("event") != null) {
                stub.setEvent("event", transientMap.get("event"));
            }
            if (transientMap.containsKey("result") && transientMap.get("result") != null) {
                return newSuccessResponse(transientMap.get("result"));
            }
        }
        return newSuccessResponse();
    }
    // Deletes an entity from state
    private Response delete(ChaincodeStub stub, List<String> args) {
        if (args.size() != 1) {
            return newErrorResponse("Incorrect number of arguments. Expecting 1");
        }
        String key = args.get(0);
        // Delete the key from the state in ledger
        stub.delState(key);
        return newSuccessResponse();
    }
    /**
     * 链码的查询方法
     * @param stub
     * @param args
     * @return
     */
    // query callback representing the query of a chaincode
    private Response query(ChaincodeStub stub, List<String> args) {
        if (args.size() != 1) {
            return newErrorResponse("Incorrect number of arguments. Expecting name of the person to query");
        }
        String key = args.get(0);
        //byte[] stateBytes
        String val = stub.getStringState(key);
        if (val == null) {
            return newErrorResponse(String.format("Error: state for %s is null", key));
        }
        _logger.info(String.format("Query Response:\nName: %s, Amount: %s\n", key, val));
        return newSuccessResponse(val, ByteString.copyFrom(val, UTF_8).toByteArray());
    }
    /**
     * 主方法,链码的启动方法
     * @param args
     */
    public static void main(String[] args) {
        System.out.println("OpenSSL avaliable: " + OpenSsl.isAvailable());
        new SimpleChaincode().start(args);
    }
}
