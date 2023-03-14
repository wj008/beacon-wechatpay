<?php

namespace libs;

use beacon\core\CacheException;
use beacon\core\Config;
use beacon\core\Logger;
use beacon\core\Redis;
use beacon\core\Request;
use beacon\core\Util;
use GuzzleHttp;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\RequestException;
use NoopValidator;
use RuntimeException;
use WechatPay\GuzzleMiddleware\Util\AesUtil;
use WechatPay\GuzzleMiddleware\Util\PemUtil;
use WechatPay\GuzzleMiddleware\WechatPayMiddleware;

class WeChat
{
    /**
     * 获取并保存操作码
     * @return string
     * @throws GuzzleException
     * @throws CacheException
     */
    public static function getAccessToken(): string
    {
        $data = Redis::callCache('wxchat_access_token', 3600, function () {
            $weChat = Config::get('wechat.*');
            $param = [
                'appid' => $weChat['appid'],
                'secret' => $weChat['secret'],
                'grant_type' => 'client_credential'
            ];
            $client = new GuzzleHttp\Client();
            $response = $client->get('https://api.weixin.qq.com/cgi-bin/token', [
                'query' => $param
            ]);
            $body = $response->getBody()->getContents();
            return Helper::convertArray($body, []);
        });
        return $data['access_token'] ?? '';
    }

    /**
     * 获取OpenId
     * @param string $code
     * @return array|null
     * @throws CacheException
     * @throws GuzzleException
     */
    public static function getOpenId(string $code): ?array
    {
        return Redis::callCache('wechat_login_' . md5($code), 300, function () use ($code) {
            $weChat = Config::get('wechat.*');
            $param = [
                'appid' => $weChat['appid'],
                'secret' => $weChat['secret'],
                'js_code' => $code,
                'grant_type' => 'authorization_code'
            ];
            $client = new GuzzleHttp\Client();
            $response = $client->get('https://api.weixin.qq.com/sns/jscode2session', [
                'query' => $param
            ]);
            $body = $response->getBody()->getContents();
            $data = Helper::convertArray($body, []);
            if (empty($data['openid']) || empty($data['session_key'])) {
                return null;
            }
            $data['openid'] = trim($data['openid']);
            $data['session_key'] = trim($data['session_key']);
            return $data;
        });
    }

    /**
     * 获取小程序手机号码
     * @param string $code
     * @return string
     * @throws CacheException
     * @throws GuzzleException
     */
    public static function getPhoneNumber(string $code): string
    {
        $token = static::getAccessToken();
        $client = new GuzzleHttp\Client();
        $response = $client->post('https://api.weixin.qq.com/wxa/business/getuserphonenumber', [
            'query' => ['access_token' => $token],
            'json' => [
                'code' => $code
            ],
            'headers' => ['Accept' => 'application/json']
        ]);
        $body = $response->getBody()->getContents();
        $data = Helper::convertArray($body, []);
        $info = $data['phone_info'] ?? [];
        return $info['phoneNumber'] ?? '';
    }


    /**
     * 获取支付前的数据
     * @param string $openId
     * @param string $tradeNo
     * @param float $amount
     * @param string $body
     * @param string $attach
     * @param int $time_expire
     * @param string $notifyUrl
     * @return array|null
     * @throws BusException|GuzzleException
     */
    public static function prepayData(string $openId, string $tradeNo, float $amount, string $body, string $attach = '', int $time_expire = 0, string $notifyUrl = '/service/wechat_pay/notify'): ?array
    {
        $weChat = Config::get('wechat.*');
        if (empty($body)) {
            $body = $weChat['body'];
        }
        $param = [];
        $param['appid'] = $weChat['appid'];
        $param['mchid'] = $weChat['pay_mchid'];
        $param['description'] = $body;
        $param['out_trade_no'] = $tradeNo;
        if ($time_expire > 0) {
            $param['time_expire'] = date('Y-m-d', $time_expire) . 'T' . date('H:i:s', $time_expire) . '+08:00';
        }
        if (!empty($attach)) {
            $param['attach'] = $attach;
        }
        $domain = $weChat['web_domain'] ?? '';
        if (empty($domain)) {
            $domain = Request::domain(true);
        }
        $param['notify_url'] = $domain . $notifyUrl;
        $param['amount'] = [
            'total' => round($amount * 100),
            'currency' => 'CNY',
        ];
        $param['payer'] = [
            'openid' => $openId,
        ];
        //微信v3
        $data = self::postData('https://api.mch.weixin.qq.com/v3/pay/transactions/jsapi', $param);
        return self::getPayData($data);
    }

    /**
     * 后台下单方式，不需要OPENID
     * @param string $tradeNo
     * @param float $amount
     * @param string $body
     * @param string $attach
     * @param int $time_expire
     * @param string $notifyUrl
     * @return array
     * @throws BusException
     * @throws GuzzleException
     */
    public static function nativePay(string $tradeNo, float $amount, string $body, string $attach = '', int $time_expire = 0, string $notifyUrl = '/service/wechat_pay/notify'): array
    {
        $weChat = Config::get('wechat.*');
        if (empty($body)) {
            $body = $weChat['body'];
        }
        $param = [];
        $param['appid'] = $weChat['appid'];
        $param['mchid'] = $weChat['pay_mchid'];
        $param['description'] = $body;
        $param['out_trade_no'] = $tradeNo;
        if ($time_expire > 0) {
            $param['time_expire'] = date('Y-m-d', $time_expire) . 'T' . date('H:i:s', $time_expire) . '+08:00';
        }
        if (!empty($attach)) {
            $param['attach'] = $attach;
        }
        $domain = $weChat['web_domain'] ?? '';
        if (empty($domain)) {
            $domain = Request::domain(true);
        }
        $param['notify_url'] = $domain . $notifyUrl;
        $param['amount'] = [
            'total' => round($amount * 100),
            'currency' => 'CNY',
        ];
        //微信v3
        return self::postData('https://api.mch.weixin.qq.com/v3/pay/transactions/native', $param);
    }

    /**
     * 提交退款
     * @param string $transactionNumber
     * @param string $tradeNo
     * @param string $refundNo
     * @param float $total
     * @param float $refund
     * @param string $reason
     * @param string $notifyUrl
     * @return array
     * @throws BusException
     * @throws GuzzleException
     */
    public static function applyRefund(string $transactionNumber, string $tradeNo, string $refundNo, float $total, float $refund, string $reason = '', string $notifyUrl = '/service/wechat_pay/refund'): array
    {
        $weChat = Config::get('wechat.*');
        $param = [];
        $param['transaction_id'] = $transactionNumber;
        $param['out_trade_no'] = $tradeNo;
        $param['out_refund_no'] = $refundNo;
        if (!empty($reason)) {
            $param['reason'] = $reason;
        }
        $domain = $weChat['web_domain'] ?? '';
        if (empty($domain)) {
            $domain = Request::domain(true);
        }
        $param['notify_url'] = $domain . $notifyUrl;
        $amount = [
            'refund' => round($refund * 100),
            'total' => round($total * 100),
            'currency' => 'CNY'
        ];
        $param['amount'] = $amount;
        return self::postData('https://api.mch.weixin.qq.com/v3/refund/domestic/refunds', $param);
    }


    /**
     * 支付回调通知
     * @return void
     */
    public static function payNotify(): void
    {
        try {
            $data = WeChat::getNotifyData('TRANSACTION.SUCCESS');
            $tradeNo = $data['out_trade_no'];
            $transactionNumber = $data['transaction_id'];
            if (empty($payNumber)) {
                return;
            }
            $amount = $data['amount'];
            $paidAmount = floatval(intval($amount['payer_total']) / 100);
            $callback = Config::get('wechat.notify_callback');
            if (is_callable($callback)) {
                call_user_func($callback, $tradeNo, $paidAmount, $transactionNumber);
            }
            header('HTTP/1.1 200 OK');
            exit;
        } catch (\Exception $exception) {
            Logger::error($exception);
            header('HTTP/1.1 404 Not Found');
            echo json_encode([
                'code' => 'FAIL',
                'message' => '失败'
            ]);
            exit;
        }
    }

    /**
     * 退款回调通知
     * @return void
     */
    public static function refundNotify(): void
    {
        try {
            $data = WeChat::getNotifyData('REFUND.SUCCESS');
            $refundNo = $data['out_refund_no'];
            $refundNumber = $data['refund_id'];
            if (empty($refundNumber)) {
                return;
            }
            $amount = $data['amount'];
            $refundAmount = floatval(intval($amount['payer_refund']) / 100);
            $callback = Config::get('wechat.refund_callback');
            if (is_callable($callback)) {
                call_user_func($callback, $refundNo, $refundAmount, $refundNumber);
            }
            header('HTTP/1.1 200 OK');
            exit;
        } catch (\Exception $exception) {
            Logger::error($exception);
            header('HTTP/1.1 404 Not Found');
            echo json_encode([
                'code' => 'FAIL',
                'message' => '失败'
            ]);
            exit;
        }
    }

    /**
     * 关闭订单
     * @param string $tradeNo
     * @return mixed|null
     * @throws BusException
     * @throws GuzzleException
     */
    public static function close(string $tradeNo): mixed
    {
        //微信v3
        $weChat = Config::get('wechat.*');
        $param = [];
        $param['mchid'] = $weChat['pay_mchid'];
        return self::postData('https://api.mch.weixin.qq.com/v3/pay/transactions/out-trade-no/' . $tradeNo . '/close', $param);
    }

    /**
     * 获取支付数据
     * @param array $preData
     * @return array
     */
    private static function getPayData(array $preData): array
    {
        $weChat = Config::get('wechat.*');
        $payData = [];
        $payData['appId'] = $weChat['appid'];
        $payData['timeStamp'] = strval(time());
        $payData['nonceStr'] = Util::randWord(20);
        $payData['package'] = 'prepay_id=' . $preData['prepay_id'];
        $payData['paySign'] = self::makeSign($payData);
        $payData['signType'] = 'RSA';
        return $payData;
    }

    /**
     * 获取通知数据
     * @param string $eventType
     * @return array
     * @throws BusException
     */
    private static function getNotifyData(string $eventType): array
    {
        $weChat = Config::get('wechat.*');
        if (Request::isPost()) {
            $res = file_get_contents('php://input');
            try {
                if (!preg_match('@^\{.*\}$@', $res)) {
                    throw new BusException('回调数据有误1', 1);
                }
                $ret = json_decode($res, true);
                if (!is_array($ret)) {
                    throw new BusException('回调数据有误2', 2);
                }
                if ($ret['event_type'] != $eventType) {
                    throw new BusException('处理业务失败', 0);
                }
                $resource = $ret['resource'];
                $aesDecoder = new AesUtil($weChat['pay_secret']);
                $strData = $aesDecoder->decryptToString($resource['associated_data'], $resource['nonce'], $resource['ciphertext']);
                if (!preg_match('@^\{.*\}$@', $strData)) {
                    throw new BusException('回调数据有误3', 3);
                }
                $data = json_decode($strData, true);
                if (!is_array($data)) {
                    throw new BusException('回调数据有误3', 4);
                }
                return $data;
            } catch (\Exception $e) {
                Logger::error($e);
                throw new BusException('回调数据有误4', 5);
            }
        }
        throw new BusException('回调数据有误5', 6);
    }


    /**
     * 证书签名
     * @param array $data
     * @return string
     */
    private static function makeSign(array $data): string
    {
        if (!in_array('sha256WithRSAEncryption', openssl_get_md_methods(true))) {
            throw new RuntimeException("当前PHP环境不支持SHA256withRSA");
        }
        // 拼接生成签名所需的字符串
        $message = '';
        foreach ($data as $value) {
            $message .= $value . "\n";
        }
        // 商户私钥
        $apiclient_key_path = Config::get('wechat.apiclient_key_path', 'cert/apiclient_key.pem');
        $keyPath = Util::path(ROOT_DIR, $apiclient_key_path);
        $private_key = openssl_pkey_get_private(file_get_contents($keyPath));
        // 生成签名
        openssl_sign($message, $sign, $private_key, 'sha256WithRSAEncryption');
        return base64_encode($sign);
    }

    /**
     * 提交数据
     * @param string $url
     * @param array $param
     * @return mixed|null
     * @throws BusException
     * @throws GuzzleException
     */
    private static function postData(string $url, array $param): mixed
    {
        $weChat = Config::get('wechat.*');
        $merchantId = $weChat['pay_mchid']; // 商户号
        $merchantSerialNumber = $weChat['serial_number']; // 商户API证书序列号
        $apiclient_key_path = Config::get('wechat.apiclient_key_path', 'cert/apiclient_key.pem');
        $wechat_cert_path = Config::get('wechat.wechat_cert_path', 'runtime/wechat_cert.pem');
        $keyPath = Util::path(ROOT_DIR, $apiclient_key_path);
        $certPath = Util::path(ROOT_DIR, $wechat_cert_path);
        //如果文件不存在，或者 文件超过10小时
        if (!file_exists($certPath) || filemtime($certPath) < time() - 10 * 3600) {
            Logger::log('重新下载证书...');
            $down = self::downCert($certPath);
            if ($down === false) {
                throw new BusException('下载平台证书失败');
            }
            sleep(1);
        }
        $merchantPrivateKey = PemUtil::loadPrivateKey($keyPath); // 商户私钥
        $certificate = PemUtil::loadCertificate($certPath); // 微信支付平台证书
        $builder = WechatPayMiddleware::builder();
        $builder->withMerchant($merchantId, $merchantSerialNumber, $merchantPrivateKey); // 传入商户相关配置
        $builder->withWechatPay([$certificate]); // 可传入多个微信支付平台证书，参数类型为array
        $middleware = $builder->build();
        $stack = GuzzleHttp\HandlerStack::create();
        $stack->push($middleware, 'wechatpay');
        $client = new GuzzleHttp\Client(['handler' => $stack]);
        try {
            $resp = $client->request('POST', $url, [
                'json' => $param,
                'headers' => ['Accept' => 'application/json']
            ]);
        } catch (RequestException $e) {
            if ($e->hasResponse()) {
                $statusCode = $e->getResponse()->getStatusCode();
                $dataD = $e->getResponse()->getBody();
                if (Util::isJson($dataD)) {
                    $data = Helper::convertArray($dataD, []);
                    Logger::log($data);
                    if (isset($data['message'])) {
                        throw new BusException('支付失败:' . $data['message'], $statusCode);
                    }
                }
                throw new BusException('支付失败', $statusCode);
            }
            return null;
        }
        $body = $resp->getBody()->getContents();
        return json_decode($body, true);
    }

    /**
     * 下载微信平台证书
     * @param string $certPath
     * @return bool
     * @throws GuzzleException
     */
    private static function downCert(string $certPath): bool
    {
        $weChat = Config::get('wechat.*');
        $merchantId = $weChat['pay_mchid']; // 商户号
        $merchantSerialNumber = $weChat['serial_number']; // 商户API证书序列号

        $apiclient_key_path = Config::get('wechat.apiclient_key_path', 'cert/apiclient_key.pem');
        $keyPath = Util::path(ROOT_DIR, $apiclient_key_path);
        $merchantPrivateKey = PemUtil::loadPrivateKey($keyPath); // 商户私钥
        $builder = WechatPayMiddleware::builder();
        $builder->withMerchant($merchantId, $merchantSerialNumber, $merchantPrivateKey);
        $builder->withValidator(new NoopValidator);
        $middleware = $builder->build();
        $url = 'https://api.mch.weixin.qq.com/v3/certificates';
        $stack = GuzzleHttp\HandlerStack::create();
        $stack->push($middleware, 'wechatpay');
        $client = new GuzzleHttp\Client(['handler' => $stack]);
        try {
            $resp = $client->request('GET', $url, [
                'headers' => ['Accept' => 'application/json']
            ]);
        } catch (RequestException $e) {
            // 进行错误处理
            if ($e->hasResponse()) {
                Logger::log('1getStatusCode', $e->getResponse()->getStatusCode() . ' ' . $e->getResponse()->getReasonPhrase() . "\n");
                Logger::log('1getBody', $e->getResponse()->getBody() . "\n");
            }
            return false;
        }
        $body = $resp->getBody();
        $data = json_decode($body->getContents(), true);
        $data = $data['data'][0];
        $encrypt = $data['encrypt_certificate'];
        $aesDecoder = new AesUtil($weChat['pay_secret']);
        $certData = $aesDecoder->decryptToString($encrypt['associated_data'], $encrypt['nonce'], $encrypt['ciphertext']);
        file_put_contents($certPath, $certData);
        return true;
    }


}