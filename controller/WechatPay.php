<?php

namespace app\service\controller;

use beacon\core\Controller;
use beacon\core\Method;
use libs\WeChat;

class WechatPay extends Controller
{
    /**
     * @return void
     */
    #[Method(act: 'notify', method: Method::POST, contentType: 'json')]
    public function notify(): void
    {
        WeChat::payNotify();
    }

    #[Method(act: 'refund', method: Method::POST, contentType: 'json')]
    public function refund()
    {
        WeChat::refundNotify();
    }
}