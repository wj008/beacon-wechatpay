<?php
return [
    //接受通知的返回地址
    'web_domain' => 'http://ceshi.local.tisapi.com',
    //小程序ID
    'appid' => '',
    //小程序密钥
    'secret' => '',
    //v3接口配置
    //商户号
    'pay_mchid' => '',
    //支付密钥
    'pay_secret' => '',
    //证书序列号
    'serial_number' => '',

    //商户API证书路径
    'apiclient_key_path' => 'cert/apiclient_key.pem',
    //微信证书路径(缓存路径)
    'wechat_cert_path' => 'runtime/wechat_cert.pem',
    //证书序列号
    'body' => '某某订单购买支付',
    //支付通知回调函数
    'notify_callback' => ['libs\\Payment', 'confirm'],
    //退款通知回调函数
    'refund_callback' => ['libs\\Refund', 'confirm'],
];