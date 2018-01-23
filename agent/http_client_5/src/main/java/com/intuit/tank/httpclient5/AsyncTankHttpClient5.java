package com.intuit.tank.httpclient5;

import com.intuit.tank.http.*;
import com.intuit.tank.http.TankHttpUtil.PartHolder;
import com.intuit.tank.logging.LogEventType;
import com.intuit.tank.vm.settings.AgentConfig;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.apache.hc.client5.http.async.methods.SimpleHttpRequest;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.NTCredentials;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.config.CookieSpecs;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.cookie.BasicCookieStore;
import org.apache.hc.client5.http.cookie.Cookie;
import org.apache.hc.client5.http.entity.mime.MultipartEntityBuilder;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.cookie.BasicClientCookie;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.impl.routing.DefaultProxyRoutePlanner;
import org.apache.hc.client5.http.nio.AsyncClientConnectionManager;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.client5.http.ssl.H2TlsStrategy;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.concurrent.FutureCallback;
import org.apache.hc.core5.http.*;
import org.apache.hc.core5.http.nio.ssl.TlsStrategy;
import org.apache.hc.core5.ssl.SSLContexts;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.annotation.Nonnull;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.*;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPInputStream;

/*
 * #%L
 * Intuit Tank Agent (apiharness)
 * %%
 * Copyright (C) 2011 - 2015 Intuit Inc.
 * %%
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * #L%
 */

public class AsyncTankHttpClient5 implements TankHttpClient {

    static Logger LOG = LogManager.getLogger(AsyncTankHttpClient5.class);

    private CloseableHttpAsyncClient httpclient;
    private HttpClientContext context;
    private RequestConfig requestConfig;
    private SSLConnectionSocketFactory sslsf;
    private AsyncClientConnectionManager cm;
    private boolean proxyOn = false;

    /**
     * no-arg constructor for client
     */
    public AsyncTankHttpClient5() {
        final TlsStrategy tlsStrategy = new H2TlsStrategy(
                SSLContexts.createDefault(),
                NoopHostnameVerifier.INSTANCE) {

            // IMPORTANT uncomment the following method when running Java 9 or older
            // in order to avoid the illegal reflective access operation warning
//            @Override
//            protected TlsDetails createTlsDetails(final SSLEngine sslEngine) {
//                return new TlsDetails(sslEngine.getSession(), sslEngine.getApplicationProtocol());
//            }
        };

        cm = PoolingAsyncClientConnectionManagerBuilder.create()
                .setTlsStrategy(tlsStrategy)
                .build();
        
        httpclient = HttpAsyncClients.custom().setConnectionManager(cm).build();
        requestConfig = RequestConfig.custom()
        		.setConnectTimeout(30, TimeUnit.SECONDS)
        		.setCircularRedirectsAllowed(true)
        		.setAuthenticationEnabled(true)
        		.setRedirectsEnabled(true)
        		.setCookieSpec(CookieSpecs.STANDARD)
                .setMaxRedirects(100).build();

        // Make sure the same context is used to execute logically related
        // requests
        context = HttpClientContext.create();
        context.setCredentialsProvider(new BasicCredentialsProvider());
        context.setCookieStore(new BasicCookieStore());
        context.setRequestConfig(requestConfig);
    }

    public void setConnectionTimeout(long connectionTimeout) {
        requestConfig = RequestConfig.custom()
        		.setConnectTimeout((int) connectionTimeout, TimeUnit.MILLISECONDS)
        		.setCircularRedirectsAllowed(true)
        		.setAuthenticationEnabled(true)
                .setRedirectsEnabled(true)
                .setCookieSpec(CookieSpecs.STANDARD)
                .setMaxRedirects(100).build();
        context.setRequestConfig(requestConfig);
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.intuit.tank.httpclient3.TankHttpClient#doGet(com.intuit.tank.http.
     * BaseRequest)
     */
    @Override
    public void doGet(BaseRequest request) {
        SimpleHttpRequest httpget = SimpleHttpRequest.get(request.getRequestUrl());
        sendRequest(request, httpget, request.getBody());
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.intuit.tank.httpclient3.TankHttpClient#doPut(com.intuit.tank.http.
     * BaseRequest)
     */
    @Override
    public void doPut(BaseRequest request) {
        SimpleHttpRequest httpput = SimpleHttpRequest.put(request.getRequestUrl());
        // Multiple calls can be expensive, so get it once
        String requestBody = request.getBody();
        httpput.setBodyText(requestBody, ContentType.create(request.getContentType(), request.getContentTypeCharSet()));
        sendRequest(request, httpput, requestBody);
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.intuit.tank.httpclient3.TankHttpClient#doDelete(com.intuit.tank.http.
     * BaseRequest)
     */
    @Override
    public void doDelete(BaseRequest request) {
        SimpleHttpRequest httpdelete = SimpleHttpRequest.delete(request.getRequestUrl());
        // Multiple calls can be expensive, so get it once
        String requestBody = request.getBody();
        String type = request.getHeaderInformation().get("Content-Type");
        if (StringUtils.isBlank(type)) {
            request.getHeaderInformation().put("Content-Type", "application/json");
        }
        sendRequest(request, httpdelete, requestBody);
    }
    
    /*
     * (non-Javadoc)
     * 
     * @see
     * com.intuit.tank.httpclient3.TankHttpClient#doOptions(com.intuit.tank.http.
     * BaseRequest)
     */
    @Override
    public void doOptions(BaseRequest request) {
        SimpleHttpRequest httpoptions = SimpleHttpRequest.options(request.getRequestUrl());
        // Multiple calls can be expensive, so get it once
        String requestBody = request.getBody();
        String type = request.getHeaderInformation().get("Content-Type");
        if (StringUtils.isBlank(type)) {
            request.getHeaderInformation().put("Content-Type", "application/json");
        }
        sendRequest(request, httpoptions, requestBody);
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.intuit.tank.httpclient3.TankHttpClient#doPost(com.intuit.tank.http.
     * BaseRequest)
     */
    @Override
    public void doPost(BaseRequest request) {
        SimpleHttpRequest httppost = SimpleHttpRequest.post(request.getRequestUrl());
        String requestBody = request.getBody();
        //if (BaseRequest.CONTENT_TYPE_MULTIPART.equalsIgnoreCase(request.getContentType())) {
        //    httppost.buildParts(request);
        //} else {
            httppost.setBodyText(requestBody, ContentType.create(request.getContentType(), request.getContentTypeCharSet()));
        //}
        sendRequest(request, httppost, requestBody);
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.intuit.tank.httpclient3.TankHttpClient#addAuth(com.intuit.tank.http.
     * AuthCredentials)
     */
    @Override
    public void addAuth(AuthCredentials creds) {
        String protocol = null;
        String host = (StringUtils.isBlank(creds.getHost()) || "*".equals(creds.getHost())) ? null : creds.getHost();
        String realm = (StringUtils.isBlank(creds.getRealm()) || "*".equals(creds.getRealm())) ? null : creds.getRealm();
        int port = NumberUtils.toInt(creds.getPortString(), -1);
        String scheme = creds.getScheme() != null ? creds.getScheme().getRepresentation() : null;
        AuthScope scope = new AuthScope(protocol, host, port, realm, scheme);
        BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        if (AuthScheme.NTLM == creds.getScheme()) {
            credentialsProvider.setCredentials(scope, new NTCredentials(creds.getUserName(), creds.getPassword().toCharArray(), "tank-test", creds.getRealm()));
        } else {
        	credentialsProvider.setCredentials(scope, new UsernamePasswordCredentials(creds.getUserName(), creds.getPassword().toCharArray()));
        }
        context.setCredentialsProvider(credentialsProvider);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.intuit.tank.httpclient3.TankHttpClient#clearSession()
     */
    @Override
    public void clearSession() {
        context.getCookieStore().clear();
    }

    /**
     * 
     */
    @Override
    public void setCookie(TankCookie cookie) {
        BasicClientCookie c = new BasicClientCookie(cookie.getName(), cookie.getValue());
        c.setDomain(cookie.getDomain());
        c.setPath(cookie.getPath());
        context.getCookieStore().addCookie(c);

    }

    @Override
    public void setProxy(String proxyhost, int proxyport) {
        if (StringUtils.isNotBlank(proxyhost)) {
            HttpHost proxy = new HttpHost(proxyhost, proxyport);
            DefaultProxyRoutePlanner routePlanner = new DefaultProxyRoutePlanner(proxy);
            httpclient = HttpAsyncClients.custom().setConnectionManager(cm).setRoutePlanner(routePlanner).build();
            proxyOn = true;
        } else if (proxyOn){
            httpclient = HttpAsyncClients.custom().setConnectionManager(cm).build();
            proxyOn = false;
        }
    }

    private void sendRequest(BaseRequest request, @Nonnull SimpleHttpRequest method, String requestBody) {
        try {
            LOG.debug(request.getLogUtil().getLogMessage("About to " + method.getMethod() + " request to " + method.getRequestUri() + " with requestBody  " + requestBody, LogEventType.Informational));
            List<String> cookies = new ArrayList<String>();
            if (context.getCookieStore().getCookies() != null) {
                for (Cookie cookie : context.getCookieStore().getCookies()) {
                    cookies.add("REQUEST COOKIE: " + cookie.toString());
                }
            }
            request.logRequest(method.getRequestUri(), requestBody, method.getMethod(), request.getHeaderInformation(), cookies, false);
            setHeaders(request, method, request.getHeaderInformation());
            long startTime = System.currentTimeMillis();
            request.setTimestamp(new Date(startTime));
             final Future<SimpleHttpResponse> future = httpclient.execute(
                    method, context,
                    new FutureCallback<SimpleHttpResponse>() {

                        @Override
                        public void completed(final SimpleHttpResponse response) {
                            // read response body
                            byte[] responseBody = new byte[0];
                            // check for no content headers
                            if (response.getCode() != 203 && response.getCode() != 202 && response.getCode() != 204) {
                                try {
                                    responseBody = response.getBody().getBodyBytes();
                                } catch (Exception e) {
                                    LOG.warn("could not get response body: " + e);
                                }
                            }
                            long waitTime = System.currentTimeMillis() - startTime;
                            processResponse(responseBody, waitTime, request, response.getReasonPhrase(), response.getCode(), response.getAllHeaders());
                            if (waitTime != 0) {
                                doWaitDueToLongResponse(request, waitTime, method.getRequestUri());
                            }
                        }

                        @Override
                        public void failed(final Exception ex) {
                            System.out.println(method.getRequestUri() + "->" + ex);
                        }

                        @Override
                        public void cancelled() {
                            System.out.println(method.getRequestUri() + " cancelled");
                        }

                    });
            future.get();

        } catch (Exception ex) {
            LOG.error(request.getLogUtil().getLogMessage("Could not do " + method.getMethod() + " to url " + method.getRequestUri() + " |  error: " + ex.toString(), LogEventType.IO), ex);
            throw new RuntimeException(ex);
        } finally {
            if (method.getMethod().equalsIgnoreCase("post") && request.getLogUtil().getAgentConfig().getLogPostResponse()) {
                LOG.info(request.getLogUtil().getLogMessage(
                        "Response from POST to " + request.getRequestUrl() + " got status code " + request.getResponse().getHttpCode() + " BODY { " + request.getResponse().getBody() + " }",
                        LogEventType.Informational));
            }
        }
    }

    /**
     * Wait for the amount of time it took to get a response from the system if
     * the response time is over some threshold specified in the properties
     * file. This will ensure users don't bunch up together after a blip on the
     * system under test
     * 
     * @param responseTime
     *            - response time of the request; this will also be the time to
     *            sleep
     * @param uri
     */
    private void doWaitDueToLongResponse(BaseRequest request, long responseTime, String uri) {
        try {
            AgentConfig config = request.getLogUtil().getAgentConfig();
            long maxAgentResponseTime = config.getMaxAgentResponseTime();
            if (maxAgentResponseTime < responseTime) {
                long waitTime = Math.min(config.getMaxAgentWaitTime(), responseTime);
                LOG.warn(request.getLogUtil().getLogMessage("Response time to slow | delaying " + waitTime + " ms | url --> " + uri, LogEventType.Script));
                Thread.sleep(waitTime);
            }
        } catch (InterruptedException e) {
            LOG.warn("Interrupted", e);
        }
    }

    /**
     * Process the response data
     */
    private void processResponse(byte[] bResponse, long waitTime, BaseRequest request, String message, int httpCode, Header[] headers) {
        BaseResponse response = request.getResponse();
        try {
            if (response == null) {
                // Get response header information
                String contentType = "";
                for (Header h : headers) {
                    if ("ContentType".equalsIgnoreCase(h.getName())) {
                        contentType = h.getValue();
                        break;
                    }
                }
                response = TankHttpUtil.newResponseObject(contentType);
                request.setResponse(response);
            }

            // Get response detail information
            response.setHttpMessage(message);
            response.setHttpCode(httpCode);

            // Get response header information
            for (int h = 0; h < headers.length; h++) {
                response.setHeader(headers[h].getName(), headers[h].getValue());
            }

            if (context.getCookieStore().getCookies() != null) {
                for (Cookie cookie : context.getCookieStore().getCookies()) {
                    response.setCookie(cookie.getName(), cookie.getValue());
                }
            }
            response.setResponseTime(waitTime);
            String contentType = response.getHttpHeader("Content-Type");
            String contentEncode = response.getHttpHeader("Content-Encoding");
            if (BaseResponse.isDataType(contentType) && contentEncode != null && contentEncode.toLowerCase().contains("gzip")) {
                // decode gzip for data types
                try {
                    GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(bResponse));
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    IOUtils.copy(in, out);
                    bResponse = out.toByteArray();
                } catch (Exception e) {
                    LOG.warn(request.getLogUtil().getLogMessage("cannot decode gzip stream: " + e, LogEventType.System));
                }
            }
            response.setResponseBody(bResponse);

        } catch (Exception ex) {
            LOG.warn("Unable to get response: " + ex.getMessage());
        } finally {
            response.logResponse();
        }
    }

    /**
     * Set all the header keys
     *
     * @param request
     * @param method
     * @param headerInformation
     */
    @SuppressWarnings("rawtypes")
    private void setHeaders(BaseRequest request, SimpleHttpRequest method, HashMap<String, String> headerInformation) {
        try {
            Set set = headerInformation.entrySet();
            Iterator iter = set.iterator();

            while (iter.hasNext()) {
                Map.Entry mapEntry = (Map.Entry) iter.next();
                method.setHeader((String) mapEntry.getKey(), (String) mapEntry.getValue());
            }
        } catch (Exception ex) {
            LOG.warn(request.getLogUtil().getLogMessage("Unable to set header: " + ex.getMessage(), LogEventType.System));
        }
    }


    private HttpEntity buildParts(BaseRequest request) {
        MultipartEntityBuilder builder = MultipartEntityBuilder.create();
        for (PartHolder h : TankHttpUtil.getPartsFromBody(request)) {
            if (h.getFileName() == null) {
                if (h.isContentTypeSet()) {
                    builder.addTextBody(h.getPartName(), new String(h.getBodyAsString()), ContentType.create(h.getContentType()));
                } else {
                    builder.addTextBody(h.getPartName(), new String(h.getBodyAsString()));
                }
            } else {
                if (h.isContentTypeSet()) {
                    builder.addBinaryBody(h.getPartName(), h.getBody(), ContentType.create(h.getContentType()), h.getFileName());
                } else {
                    builder.addBinaryBody(h.getFileName(), h.getBody());
                }
            }
        }
        return builder.build();
    }
    

}
