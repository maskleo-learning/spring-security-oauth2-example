These are the Spring Security OAuth sample apps and integration tests.
They are split into OAuth (1a) and OAuth2 samples.  Look in the
subdirectory `oauth` and `oauth2` respectively for components of the
sample you are interested in.  They are broadly speaking similar
functionally - there are two web apps, one (`sparklr`) is a provider
or OAuth services, and the other (`tonr`) is a consumer of the
services.  The `tonr` app is also able to consume external resources
(e.g. Facebook), and the precise external resource it consumes has
been chosen to show the use of the relevant protocol.

The `sparklr` app is a photo storage and browsing service, but it
doesn't know how to print your photos.  Thats where `tonr` comes in.
You go to `tonr` to browse the photos that are stored in `sparklr` and
"print" them (this feature is not actually implemented).  The `tonr`
app has to get your permission to access the photos, but only for read
access - this is the key separation of concerns that is offered by
OAuth protocols: `sparklr` is able to ask the user to authorize `tonr`
to read his photos for the purpose of printing them.

To run the apps the easiest thing is to first install all the
artifacts using `mvn install` and then go to the `tonr` directory (in
`oauth` or `oauth2`) and run `mvn tomcat7:run`.  You can also use the
command line to build war files with `mvn package` and drop them in
your favourite server, or you can run them directly from an IDE.

Visit `http://localhost:8080/tonr2` in a browser and go to the
`sparklr` tab.  The result should be:

* You are prompted to authenticate with `tonr` (the login screen tells
  you the users available and their passwords)
  
* The correct authorization is not yet in place for `tonr` to access
  your photos on `sparklr` on your behalf, so `tonr` redirects your
  browser to the `sparklr` UI to get the authorization.

* You are prompted to authenticate with `sparklr`.

* Then `sparklr` will ask you if you authorize `tonr` to access your
  photos.
  
* If you say "yes" then your browser will be redirected back to `tonr`
  and this time the correct authorization is present, so you will be
  able to see your photos.

## How to build the WAR files

Use Maven (2.2.1 works) and, from this directory do 

    $ mvn package

and then look in `*/{sparklr,tonr}/target` for the war files.  Deploy
them with context roots `{/sparklr,/tonr}` (for OAuth 1) and
`{/sparklr2,/tonr2}` (for OAuth 2) respectively in your favourite web
container, and fire up the `tonr` app to see the two working together.

## How to deploy in Eclipse (e.g. STS)

To deploy the apps in Eclipse you will need the Maven plugin (`m2e`)
and the Web Tools Project (WTP) plugins.  If you have SpringSource
Toolsuite (STS) you should already have those, aso you can deploy the
apps very simply.  (Update the WTP plugin to at least version 0.12 at
http://download.eclipse.org/technology/m2e/releases if you have an older
one, or the context roots for the apps will be wrong.)

* Ensure the Spring Security OAuth dependencies are available locally
first.  You can do this by importing all projects, or by building on
the command line before importing the samples (using `mvn install`).

* Import the projects:

        File->Import...->Maven->Existing Maven Projects->Next

  browse to the parent directory containing all the
  samples and press `Finish`.
  
* Wait for the projects to build, and then just right click on the two
  webapps (`sparklr` and `tonr` or `sparklr2` and `tonr2`) and `Run
  As` then `Run on Server`.  If you have a server set up already
  (e.g. tcServer is probably there out of teh box) select that, or
  else create a new server, and follow the dialogues.
  
  If you have a server instance set up you can also drag and drop the
  apps to a server instance (e.g. tcServer or Tomcat) in the `Servers`
  View.

* Visit the `tonr` app in a browser
  (e.g. [http://localhost:8080/tonr2](http://localhost:8080/tonr2)).
  
  
这些是 `Spring Security OAuth` 示例应用程序和集成测试。它们分为 `OAuth（1a）` 和 `OAuth2` 样本。在子目录 `oauth` 和 `oauth2` 中分别查看您感兴趣
的示例组件。它们在功能上大致相似 - 有两个 `Web` 应用程序，一个（`sparklr`）是提供程序或 `OAuth` 服务，另一个（`tonr`）是服务的消费者。`tonr` 应用
程序也能够消耗外部资源（例如 `Facebook` ），并且已经选择了其消耗的精确外部资源来显示相关协议的使用。

`Sparklr` 应用程序是一种照片存储和浏览服务，但它不知道如何打印照片。这是 `tonr` 进来的地方。你去 `tonr` 浏览存储在 `sparklr` 中的照片并“打印”它们
（这个功能并没有实际实现。`tonr` 应用程序必须访问您的权限才能访问照片，但仅限于读取访问 - 这是 `OAuth` 协议提供的关键问题的关键分离：`sparklr` 能够
要求用户授权 `tonr` 阅读他的照片以便打印它们。

您也可以使用命令行通过 `mvn Package` 构建 `war` 文件并将它们放入您喜欢的服务器中，也可以直接从 `IDE` 运行它们。

在浏览器中访问 `http://localhost:8080/tonr2` 并转到 `sparklr` 选项卡。结果应该是：

系统会提示您使用 `tonr` 进行身份验证（登录屏幕会告诉您可用用户及其密码）

对于 `tonr` 代表您在 `sparklr` 上访问您的照片的正确授权还没有到位，所以 `tonr` 会将您的浏览器重定向到 `sparklr UI` 以获得授权。

系统会提示您使用sparklr进行身份验证。

然后sparklr会问你是否授权tonr访问你的照片。

如果你说“是”，那么你的浏览器将被重定向回tonr，这次有正确的授权，所以你将能够看到你的照片。

如何构建WAR文件
使用Maven（2.2.1作品），并从该目录中执行

$ mvn包
然后查看战争文件的* / {sparklr，tonr} / target。分别在您最喜欢的Web容器中为其部署上下文根{/ sparklr，/ tonr}（用于OAuth 1）和{/ sparklr2，/ tonr2}（用于OAuth 2），然后启动tonr应用程序以查看两者协同工作。

如何在Eclipse中部署（例如STS）
要在Eclipse中部署应用程序，您需要Maven插件（m2e）和Web Tools Project（WTP）插件。如果你有SpringSource Toolsuite（STS），你应该已经有了这些，你也可以非常简单地部署应用程序。 WTP插件至少在http://download.eclipse.org/technology/m2e/releases上版本为0.12，如果你有一个旧版本，或者应用程序的上下文根将是错误的。）

首先确保Spring Security OAuth依赖项在本地可用。您可以通过导入所有项目或通过在导入样本之前在命令行上构建（使用mvn install）来完成此操作。

导入项目：

文件 - >导入...-> Maven->现有的Maven项目 - >下一步
浏览到包含所有示例的父目录，然后按Finish。

等待项目建立，然后在两个webapps（sparklr和tonr或sparklr2和tonr2）上单击鼠标右键并运行，然后在服务器上运行。如果你已经建立了一个服务器（例如tcServer可能没有Box），请选择该服务器，或者创建一个新服务器，然后按照对话框进行操作。

如果您设置了服务器实例，则还可以将这些应用程序拖放到服务器视图中的服务器实例（例如tcServer或Tomcat）。

在浏览器中访问tonr应用程序（例如http：// localhost：8080 / tonr2）。
