link :https://projects.spring.io/spring-security-oauth/docs/oauth2.html

# OAuth 2 开发者指南

## 介绍

这是用于支持 `OAuth 2.0` 的用户指南。 对于 `OAuth 1.0`，一切都不一样，请参阅其[用户指南]
(https://projects.spring.io/spring-security-oauth/docs/oauth1.html)。

本用户指南分为两部分，第一部分为 `OAuth 2.0` 提供者，第二部分为 `OAuth 2.0` 客户端。 对于提供者和客户端来说，示例代码的最佳来源是[集成
测试](https://github.com/spring-projects/spring-security-oauth/tree/master/tests)和[示例应用程序]
(https://github.com/spring-projects/spring-security-oauth/tree/master/samples/oauth2)。

## `OAuth 2.0` 提供程序

`OAuth 2.0` 提供者机制负责公开受 `OAuth 2.0` 保护的资源。该配置涉及建立可独立或代表用户访问其受保护资源的 `OAuth 2.0` 客户端。 提供者
通过管理和验证用于访问受保护资源的 `OAuth 2.0` 令牌来实现此目的。 在适用的情况下，提供者还必须为用户提供接口以确认客户可以被授权访问受保护
的资源（即确认页面）。

## `OAuth 2.0` 提供程序实现

`OAuth 2.0` 中的提供者角色实际上分为授权服务和资源服务，虽然这些角色有时驻留在同一个应用程序中，但通过使用 `Spring Security OAuth`，您
可以选择将它们拆分为两个应用程序，还可以让多个共享的资源服务授权服务。对令牌的请求由 `Spring MVC` 控制器端点处理，对受保护资源的访问由标准
的 `Spring Security` 请求过滤器处理。为了实现 `OAuth 2.0` 授权服务器，`Spring Security` 过滤器链中需要以下端点：

- `AuthorizationEndpoint` 用于为授权请求提供服务。默认URL： `/oauth/authorize`。
- `TokenEndpoint` 用于为访问令牌提供服务请求。默认网址：`/oauth/token`。

以下过滤器是实现 `OAuth 2.0` 资源服务器所必需的：

`OAuth2AuthenticationProcessingFilter` 用于为给定经过身份验证的访问令牌的请求加载身份验证。

- 对于所有 `OAuth 2.0` 提供者功能，使用特殊的 `Spring OAuth` `@Configuration` 适配器简化了配置。 还有一个用于 `OAuth` 配置的 `XML`
名称空间，该架构驻留在 [`http://www.springframework.org/schema/security/spring-security-oauth2.xsd`]
(http://www.springframework.org/schema/security/spring-security-oauth2.xsd)。命名空间是 
[`http://www.springframework.org/schema/security/oauth2`](http://www.springframework.org/schema/security/oauth2)。

## 授权服务器配置

在配置授权服务器时，您必须考虑客户端用于从最终用户获取访问令牌的授权类型（例如授权代码，用户凭据，刷新令牌）。服务器的配置用于提供客户端详细
信息服和令牌服务的实现，并在全局范围内启用或禁用该机制的某些方面。但是请注意，每个客户端都可以使用特定的权限来配置，以便能够使用某些授权机制
和访问权限。即仅仅因为您的提供程序配置为支持“客户端凭据”授予类型，并不意味着特定客户端有权使用该授予类型。

`@EnableAuthorizationServer` 注释用于配置 `OAuth 2.0` 授权服务器机制，以及实现 `AuthorizationServerConfigurer` 的任何 `@Beans`
（有一个方便的适配器实现和空方法）。将以下功能委托给独立的由 `Spring` 创建并传递到 `AuthorizationServerConfigurer` 的配置器：

- `ClientDetailsS​​erviceConfigurer`：定义客户端详细信息服务的配置器。客户详细信息可以初始化，或者您可以参考现有的商店。
- `AuthorizationServerSecurityConfigurer`：定义令牌端点上的安全约束。
- `AuthorizationServerEndpointsConfigurer`：定义授权和令牌端点以及令牌服务。

提供程序配置的一个重要方面是将授权代码提供给 `OAuth` 客户端（在授权代码授权中）的方式。`OAuth` 客户端通过将最终用户引导至授权页面来获得授
权代码，其中用户可以输入其凭证，导致从提供者授权服务器重定向到具有授权代码的 `OAuth` 客户端。这个例子在 `OAuth 2` 规范中详细说明。

在 `XML` 中，有一个 `<authorization-server />` 元素以类似的方式用于配置 `OAuth 2.0` 授权服务器。

### 配置客户端细节

`ClientDetailsS​​erviceConfigurer`（来自 `AuthorizationServerConfigurer` 的回调）可用于定义客户端详细信息服务的内存中或 `JDBC` 实
现。客户的重要属性是

- `clientId`：（必填）客户端 `ID`。
- `secret`:(对可信的客户端要求）客户端秘密（如果有的话）。
- `scope`：客户受限的范围。如果作用域未定义或为空（默认），则客户端不受作用域的限制。
- `authorizedGrantTypes`：授权客户使用的授予类型。默认值为空。
- `authorities`：授予客户的机构（普通的 `Spring Security` 机构）。

通过直接访问底层存储（例如 `JdbcClientDetailsS​​ervice` 的情况下的数据库表）或通过 `ClientDetailsManager` 接口（
`ClientDetailsService` 的两个实现同时实现），可以在正在运行的应用程序中更新客户端详细信息。

 > 注意：`JDBC` 服务的模式没有与库一起打包（因为实际中可能会使用太多的变体），但是您可以从 `github` 中的测试代码开始。

### 管理令牌

`AuthorizationServerTokenServices` 接口定义了管理 `OAuth 2.0` 令牌所必需的操作。请注意以下几点：

- 创建访问令牌时，必须存储身份验证，以便接受访问令牌的资源可以稍后参考。
- 访问令牌用于加载用于授权其创建的认证。

在创建 `AuthorizationServerTokenServices` 实现时，您可能需要考虑使用可以插入许多策略的 `DefaultTokenServices` 来更改访问令牌的格式和存储。默认情
况下，它通过随机值创建令牌，并处理除委托给 `TokenStore` 的令牌持久性以外的所有内容。默认存储是内存中的实现，但还有一些其他实现可用。这里有一些关于每
个人的讨论

- 对于单个服务器，默认的 `InMemoryTokenStore` 是完美的（即在发生故障的情况下流量低并且不会热切换到备份服务器）。大多数项目可以从这里开始，也许可以
在开发模式下以这种方式进行操作，以便轻松启动不依赖项的服务器。

- `JdbcTokenStore` 是同一事物的 `JDBC` 版本，它在关系数据库中存储令牌数据。如果您可以在服务器之间共享数据库，则使用JDBC版本;如果只有一个服务器，则
扩大同一服务器的实例;如果有多个组件，则使用授权和资源服务器。要使用 `JdbcTokenStore`，你需要在类路径上使用“`spring-jdbc`”。

- 商店的 `JSON Web Token（JWT）` 版本将关于授权的所有数据编码到令牌本身中（因此根本没有后端存储这是一个显着的优势）。一个缺点是你不能轻易撤销访问令
牌，所以他们通常被授予短期过期并且撤销在刷新令牌处理。另一个缺点是，如果您在其中存储大量用户凭据信息，令牌可能会变得非常大。 `JwtTokenStore` 并不是
真正的“存储”，因为它不会保留任何数据，但它在 `DefaultTokenServices` 中的标记值和身份验证信息之间起着相同的作用。

> 注意：`JDBC` 服务的模式没有与库一起打包（因为实际中可能会使用太多的变体），但是您可以从 `github` 中的测试代码开始。请务必使用 
`@EnableTransactionManagement` 来防止客户端应用程序在创建令牌时竞争同一行的冲突。还要注意，示例模式具有明确的 `PRIMARY KEY` 声明 - 这些在并发环境
中也是必需的。

### `JWT` 令牌

要使用 `JWT` 令牌，您需要授权服务器中的 `JwtTokenStore`。资源服务器还需要能够对令牌进行解码，以便 `JwtTokenStore` 对 `JwtAccessTokenConverter` 
具有依赖性，并且授权服务器和资源服务器都需要相同的实现。令牌默认是签名的，并且资源服务器也必须能够验证签名，因此它需要与授权服务器（共享密钥或对称密
钥）相同的对称（签名）密钥，或者它需要公共密钥（验证方密钥）与授权服务器（公私密钥或非对称密钥）中的私钥（签名密钥）相匹配。授权服务器公开授权服务器在 
`/oauth/token_key` 端点上公开的密钥（如果可用），默认情况下安全地使用访问规则“ `denyAll()`”。你可以通过在 
`AuthorizationServerSecurityConfigurer` 中注入一个标准的 `SpEL` 表达式来打开它（例如“`permitAll()`”可能是足够的，因为它是一个公钥）。

要使用 `JwtTokenStore`，你需要在你的类路径上使用“`spring-security-jwt`”（你可以在 `Spring OAuth` 的同一个 `github` 版本库中找到它，但是发布周期
不同）。

### 授予类型

`AuthorizationEndpoint` 支持的授权类型可以通过 `AuthorizationServerEndpointsConfigurer` 进行配置。默认情况下，除密码之外，所有授权类型都受支持
（请参阅下面有关如何打开它的详细信息）。以下属性影响授权类型：

- `authenticationManager`：通过注入 `AuthenticationManager` 来开启密码授权。
- `userDetailsS​​ervice`：如果您注入了 `UserDetailsS​​ervice` 或者全局配置了全局配置（例如在 `GlobalAuthenticationManagerConfigurer` 中），那
么刷新令牌授权将包含对用户详细信息的检查，以确保该帐户仍处于活动状态
- `authorizationCodeServices`：为授权代码授权定义授权代码服务（`AuthorizationCodeServices`的实例）。
- `implicitGrantService`：在 `imlpicit` 授权期间管理状态。
- `tokenGranter`：`TokenGranter`（完全控制授予和忽略上面的其他属性）

在 `XML` 中，授予类型作为 `authorization-server` 的子元素包含在内。

### 配置端点 `URL`

`AuthorizationServerEndpointsConfigurer` 有一个 `pathMapping()` 方法。 它有两个参数：

- 端点的默认（框架实现）URL路径
- 所需的自定义路径（以“/”开头）

框架提供的 `URL` 路径是 `/oauth/authorize`（授权端点），`/oauth/token`（令牌端点），`/oauth/confirm_access`（用户在此发布授权批准），
`/oauth/error`（用于呈现错误 在授权服务器中），`/oauth/check_token`（由资源服务器用于解码访问令牌）和 `/oauth/token_key`（如果使用 `JWT` 令牌，
公开密钥用于令牌验证）。

注： 授权端点 `/oauth/authorize`（或其映射替代）应该使用 `Spring Security` 进行保护，以便只有经过认证的用户才能访问。 例如使用标准的 
`Spring Security` `WebSecurityConfigurer`：

```java
   @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests().antMatchers("/login").permitAll().and()
        // default protection for all resources (including /oauth/authorize)
            .authorizeRequests()
                .anyRequest().hasRole("USER")
        // ... more configuration, e.g. for form login
    }
```

> 注意：如果您的授权服务器也是资源服务器，那么另一个安全筛选器链具有较低的优先级来控制 `API` 资源。 如果这些请求受访问令牌保护，那么您需要他们的路径
与主要面向用户的过滤器链中的路径不匹配，因此请确保包含请求匹配程序，该请求匹配程序仅在上述 `WebSecurityConfigurer` 中挑选出非 `API` 资源。

默认情况下，`Spring OAuth` 在使用客户机密钥的 `HTTP` 基本身份验证的 `@Configuration` 支持中为您保护令牌端点。 这不是在 `XML` 中的情况（所以它应该
被明确保护）。

在 `XML` 中，`<authorization-server />` 元素具有一些可用于以类似方式更改默认端点 `URL` 的属性。 必须显式启用 `/check_token` 端点（使用启用了检查
令牌的属性）。

## 自定义用户界面

大多数授权服务器端点主要由机器使用，但有一些需要UI的资源，那些是 `/oauth/confirm_access` 的 `GET` 和 `/oauth/error` 的 `HTML` 响应。它们是在框架
中使用白标签实现提供的，因此大多数真实世界的授权服务器实例都需要自己提供，以便他们可以控制样式和内容。所有你需要做的就是为这些端点提供一个带有 
`@RequestMappings` 的 `Spring MVC` 控制器，框架默认值在调度器中的优先级较低。在 `/oauth/confirm_access` 端点中，您可以期待绑定到会话的 
`AuthorizationRequest`，该会话携带需要用户批准的所有数据（默认实现是 `WhitelabelApprovalEndpoint`，因此请在这里查找要复制的起点）。您可以从该请
求中获取所有数据并根据需要进行呈现，然后所有用户需要做的就是将 `POST` 发送回 `/oauth/authorize`，并提供有关批准或拒绝授予的信息。请求参数直接传递给 
`AuthorizationEndpoint` 中的 `UserApprovalHandler`，以便您可以根据自己的需要或多或少地解释数据。默认的 `UserApprovalHandler` 取决于您是否在您的 
`AuthorizationServerEndpointsConfigurer` 中提供了一个 `ApprovalStore`（在这种情况下，它是一个 `ApprovalStoreUserApprovalHandler`）或者不是
（在这种情况下它是一个 `TokenStoreUserApprovalHandler`）。标准批准处理程序接受以下内容：

`TokenStoreUserApprovalHandler`：通过 `user_oauth_approval` 进行简单的 `yes/no` 决定等于“`true`”或“`false`”。

`ApprovalStoreUserApprovalHandler`：一组范围 `scope.*`，其中“`*`”等于所请求的范围。参数的值可以是“真实的”或“批准的”（如果用户批准授予），否则用
户被认为已经拒绝了该范围。如果至少有一个范围被批准，则授予成功。

注意：不要忘记在您为表格呈现给用户的表单中包含 `CSRF` 保护。`Spring Security` 默认预期一个名为“`_csrf`”的请求参数（并且它在请求属性中提供值）。有
关这方面的更多信息，请参阅 `Spring Security` 用户指南，或查看白标签实施的指导。

### 强制 `SSL`

纯 `HTTP` 可用于测试，但授权服务器只能在生产环境中使用 `SSL`。 您可以在安全的容器中或在代理之后运行应用程序，如果您正确设置了代理和容器（这与 
`OAuth2` 无关），它应该可以正常工作。 您可能还想使用 `Spring Security` `requiresChannel()` 约束来保护端点。 对于 `/authorize` 端点来说，您可以
将其作为正常应用程序安全性的一部分来执行。 对于 `/token` 端点，可以使用 `sslOnly()` 方法设置 `AuthorizationServerEndpointsConfigurer` 中的标
志。 在这两种情况下，安全通道设置都是可选的，但如果它在不安全的通道上检测到请求，则会导致 `Spring Security` 重定向到它认为是安全的通道。

### 自定义错误处理

授权服务器中的错误处理使用标准的 `Spring MVC` 功能，即端点本身的 `@ExceptionHandler` 方法。用户还可以向终端自己提供 
`WebResponseExceptionTranslator`，这是改变响应内容的最佳方式，而不是呈现方式。在授权端点情况下，异常委托对 `HttpMesssageConverters`（可以添加到 
`MVC` 配置）进行呈现，对于 `OAuth` 错误视图（`/oauth/error`），则将其呈现给OAuth错误视图（`/oauth/error`）。为 `HTML` 响应提供白标签错误端点，但
用户可能需要提供自定义实现（例如，只需添加 `@RequestMapping("/oauth/error")` 的 `@Controller`）。

### 将用户角色映射到范围

有时不仅限于分配给客户端的范围，还会根据用户自己的权限来限制令牌的范围。如果您在您的 `AuthorizationEndpoint` 中使用 
`DefaultOAuth2RequestFactory`，则可以设置一个标志 `checkUserScopes = true`，以将允许的范围限制为仅与那些与用户角色相匹配的范围。您还可以将一个 
`OAuth2RequestFactory` 注入到 `TokenEndpoint` 中，但如果您还安装了 `TokenEndpointAuthenticationFilter`，则该方法仅适用于（即使用密码授予） - 
您只需在 `HTTP` `BasicAuthenticationFilter` 之后添加该过滤器即可。当然，您也可以实现自己的规则，将范围映射到角色并安装您自己的 
`OAuth2RequestFactory` 版本。`AuthorizationServerEndpointsConfigurer` 允许您注入自定义的 `OAuth2RequestFactory`，以便您可以使用该功能来设置工
厂（如果使用 `@EnableAuthorizationServer`）。

## 资源服务器配置

资源服务器（可与授权服务器或单独的应用程序相同）为受 `OAuth2` 令牌保护的资源提供服务。 `Spring OAuth` 提供了一个实现这种保护的 `Spring Security` 
认证过滤器。您可以在 `@Configuration` 类上使用 `@EnableResourceServer` 将其打开，并使用 `ResourceServerConfigurer` 对其进行配置（如有必要）。
可以配置以下功能：

- `tokenServices`：定义令牌服务的 `bean`（`ResourceServerTokenServices` 的实例）。
- `resourceId：资源的 `ID`（可选，但建议并且将由 `auth` 服务器验证，如果存在的话）。
- `resourecs服务器的其他扩展点（例如 `tokenExtractor` 用于从传入请求中提取令牌）
- 请求受保护资源的匹配器（默认为全部）
- 受保护资源的访问规则（默认为普通“已认证”）
- `Spring Security中HttpSecurity` 配置器允许的受保护资源的其他自定义

`@EnableResourceServer` 批注自动向 `Spring Security` 筛选器链添加一个 `OAuth2AuthenticationProcessingFilter` 类型的筛选器。

在 `XML` 中有一个带有 `id` 属性的 `<resource-server />` 元素 - 这是一个 `servlet Filter` 的 `bean id`，然后可以手动添加到标准 
`Spring Security` 链中。

您的 `ResourceServerTokenServices` 是授权服务器的另一半合同。如果资源服务器和授权服务器在同一个应用程序中并且您使用了 `DefaultTokenServices`，那
么您不必过多考虑这一点，因为它实现了所有必需的接口，因此它自动保持一致。如果您的资源服务器是单独的应用程序，那么您必须确保您匹配授权服务器的功能并
提供知道如何正确解码令牌的 `ResourceServerTokenServices`。与授权服务器一样，您通常可以使用 `DefaultTokenServices`，而选择主要通过 
`TokenStore`（后端存储或本地编码）表示。另一种方法是 `RemoteTokenServices`，它是 `Spring OAuth` 功能（不是规范的一部分），它允许资源服务器通过授
权服务器上的 `HTTP`资源（`/oauth/check_token`）对令牌解码。如果资源服务器中没有大量流量（每个请求必须使用授权服务器进行验证），或者您能负担得起缓存
结果，则 `RemoteTokenServices` 非常方便。要使用 `/oauth /check_token` 端点，您需要通过在 `AuthorizationServerSecurityConfigurer` 中更改其访问
规则（默认为“ `denyAll()`”）来公开它，例如，

```java
    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer.tokenKeyAccess("isAnonymous() || hasAuthority('ROLE_TRUSTED_CLIENT')").checkTokenAccess(
                "hasAuthority('ROLE_TRUSTED_CLIENT')");
    }
```

在本例中，我们正在配置 `/oauth/check_token` 端点和 `/oauth/token_key` 端点（因此可信资源可以获取 `JWT` 验证的公钥）。这两个端点受到使用客户端凭证
的 `HTTP` 基本身份验证的保护。

### 配置 `OAuth` 感知表达式处理程序

您可能想要利用 `Spring Security` 基于表达式的[访问控制]
(https://docs.spring.io/spring-security/site/docs/3.2.5.RELEASE/reference/htmlsingle/#el-access))。 默认情况下，表达式处理程序将在 
`@EnableResourceServer` 设置中注册。 表达式包括 `#oauth2.clientHasRole`，`#oauth2.clientHasAnyRole` 和 `#oath2.denyClient`，它们可用于根据 
`oauth` 客户端的角色提供访问权限（请参阅 `OAuth2SecurityExpressionMethods` 以获取全面的列表）。 在 `XML` 中，您可以使用常规 `<http />` 安全配置
的表达式处理程序元素注册一个 `oauth-aware` 表达式处理程序。

## `OAuth 2.0` 客户端

`OAuth 2.0` 客户端机制负责访问其他服务器的受 `OAuth 2.0` 保护的资源。 配置涉及建立用户可能访问的相关受保护资源。 客户端可能还需要提供用于存储授权代
码和用户访问令牌的机制。

### 受保护的资源配置

受保护的资源（或“远程资源”）可以使用 `OAuth2ProtectedResourceDetails` 类型的 `bean` 定义来定义。受保护资源具有以下属性：

- `id`：资源的 `ID`。该 `id` 仅由客户端用于查找资源;它从未在 `OAuth` 协议中使用过。它也被用作 `bean` 的 `id`。
- `clientId`：`OAuth` 客户端 `ID`。这是 `OAuth` 提供商标识您的客户端的 `ID`。
- `clientSecret`：与资源相关的秘密。默认情况下，没有秘密是空的。
- `accessTokenUri`：提供访问令牌的提供者 `OAuth` 端点的 `URI`。
- `scope`：逗号分隔的字符串列表，指定对资源的访问范围。默认情况下，不会指定范围。
- `clientAuthenticationScheme`：客户端用来验证访问令牌端点的方案。建议值：“`http_basic`”和“表单”。默认值：“`http_basic`”。请参阅 `OAuth 2` 规
范的第 `2.1` 节。

不同的授权类型具有不同的 `OAuth2ProtectedResourceDetails` 的具体实现（例如 `ClientCredentialsResource` 为“`client_credentials`”授予类型）。对
于需要用户授权的授权类型，还有一个属性：

- `userAuthorizationUri`：如果用户需要授权访问资源，用户将被重定向到的 `URI`。请注意，这并非总是必需的，具体取决于支持哪些 `OAuth 2` 配置文件。

在 `XML` 中有一个 `<resource />` 元素可用于创建 `OAuth2ProtectedResourceDetails` 类型的 `bean`。它具有与上述所有属性匹配的属性。 

### 客户端配置

对于 `OAuth 2.0` 客户端，使用 `@EnableOAuth2Client` 简化配置。 这有两件事：

- 创建一个过滤器 `bean`（`ID` 为 `oauth2ClientContextFilter`）来存储当前的请求和上下文。 如果需要在请求期间进行身份验证，它将管理 `OAuth` 身份验
证 `URI` 中的重定向。

- 在请求范围内创建一个类型为 `AccessTokenRequest` 的 `bean`。 这可以由授权代码（或隐式）授权客户端使用，以保持与个别用户相关的状态不会发生冲突。

过滤器必须连接到应用程序中（例如，使用具有相同名称的 `DelegatingFilterProxy` 的 `Servlet` 初始化程序或 `web.xml` 配置）。

`AccessTokenRequest` 可以在 `OAuth2RestTemplate` 中使用，如下所示：

```java
    @Autowired
    private OAuth2ClientContext oauth2Context;
    
    @Bean
    public OAuth2RestTemplate sparklrRestTemplate() {
        return new OAuth2RestTemplate(sparklr(), oauth2Context);
    }
```

`OAuth2ClientContext` 被放置在会话范围内（为你），以保持不同用户的状态分离。 如果没有这一点，您将不得不在服务器上自己管理等效的数据结构，将传入的请
求映射到用户，并将每个用户与 `OAuth2ClientContext` 的单独实例相关联。

在 `XML` 中，有一个带有 `id` 属性的 `<client />` 元素 - 这是一个 `servlet` 过滤器的 `bean id`，它必须在 `@Configuration` 案例中映射到 `DelegatingFilterProxy`（具有相同名称）。

### 访问受保护的资源

一旦你提供了资源的所有配置，你现在可以访问这些资源。建议的访问这些资源的方法是使用 `Spring 3` 中引入的 `RestTemplate`。`Spring Security` 的 
`OAuth` 提供了 `RestTemplate` 的扩展，只需提供一个 `OAuth2ProtectedResourceDetails` 的实例。要将其与用户令牌（授权代码授权）一起使用，您应该考虑
使用 `@EnableOAuth2Client` 配置（或与 `XML` 等效的 `<oauth：rest-template />`），它会创建一些请求和会话作用域上下文对象，以便对不同用户的请求执
行不会在运行时发生冲突。

作为一般规则，`Web` 应用程序不应使用密码授权，因此如果可以使用 `AuthorizationCodeResourceDetails`，请避免使用 
`ResourceOwnerPasswordResourceDetails`。如果您绝望需要从 `Java` 客户端获得密码授权，那么使用相同的机制来配置 `OAuth2RestTemplate`，并将凭据添加
到 `AccessTokenRequest`（它是一个 `Map` 并且是临时的），而不是 `ResourceOwnerPasswordResourceDetails`（它在所有访问令牌之间共享） 。

### 持久性令牌在客户端

客户端不需要持久化令牌，但用户不必在每次重新启动客户端应用程序时都需要批准新的令牌授予。 ClientTokenServices接口定义了为特定用户保留OAuth 2.0令牌所
必需的操作。 提供了一个JDBC实现，但如果您愿意实现自己的服务以将访问令牌和关联的身份验证实例存储在持久数据库中，则可以使用该实现。 如果您想使用此功
能，您需要为OAuth2RestTemplate提供特别配置的TokenProvider，例如

```java
    @Bean
    @Scope(value = "session", proxyMode = ScopedProxyMode.INTERFACES)
    public OAuth2RestOperations restTemplate() {
        OAuth2RestTemplate template = new OAuth2RestTemplate(resource(), new DefaultOAuth2ClientContext(accessTokenRequest));
        AccessTokenProviderChain provider = new AccessTokenProviderChain(Arrays.asList(new AuthorizationCodeAccessTokenProvider()));
        provider.setClientTokenServices(clientTokenServices());
        return template;
    }
```

## 外部 `OAuth2` 提供商的客户定制

某些外部 `OAuth2` 提供者（例如 `Facebook`）没有正确实施规范，否则他们只是停留在比 `Spring Security OAuth` 更旧的规范版本。 要在客户端应用程序中使
用这些提供程序，您可能需要修改客户端基础结构的各个部分。

以 `Facebook` 为例，`tonr2` 应用程序中有一项 `Facebook` 功能（您需要更改配置以添加您自己的，有效的客户端 `ID` 和密码 - 它们很容易在 `Facebook` 
网站上生成）。

`Facebook` 令牌响应还包含一个不符合 `JSON` 条目的令牌到期时间（它们使用 `expires` 而不是 `expires_in`），所以如果您想在应用程序中使用到期时间，您
将不得不使用自定义 `OAuth2SerializationService` 对其进行手动解码。
