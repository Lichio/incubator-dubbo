/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.dubbo.rpc.proxy;

import org.apache.dubbo.common.Constants;
import org.apache.dubbo.rpc.Invoker;
import org.apache.dubbo.rpc.RpcInvocation;
import org.apache.dubbo.rpc.support.RpcUtils;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;

/**
 * Java动态代理，每一个动态代理类都必须要实现InvocationHandler这个接口，并且每一个代理类的实例都关联到了一个handler，
 * 当我们通过代理对象调用一个方法的时候，这个方法就会被转发为由实现了InvocationHandler这个接口的类的invoke方法来进行调用。
 *
 * 当调用helloService.sayHello();的时候，实际上会调用invoke()方法
 * InvokerHandler
 */
public class InvokerInvocationHandler implements InvocationHandler {

    /**
     * invoker变量的值来自ReferenceConfig的createProxy()方法中的proxyFactory.getProxy(Invoker<T> invoker)，
     * 在ReferenceConfig中，invoker变量的值最终由cluster.join()方法获得，根据扩展点的自适应加载和自动包装，
     * cluster的执行类为MockClusterWrapper（包装类） -> FailoverCluster（默认值，根据配置变化），
     * 返回的Invoker类为MockClusterInvoker（包装类） -> FailoverClusterInvoker（默认值，根据配置变化）
     **/
    private final Invoker<?> invoker;

    public InvokerInvocationHandler(Invoker<?> handler) {
        this.invoker = handler;
    }

    /**
     *
     * @param proxy 代理类对象
     * @param method 需要调用的方法
     * @param args 方法参数
     * @return
     * @throws Throwable
     */
    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        String methodName = method.getName();
        Class<?>[] parameterTypes = method.getParameterTypes();
        if (method.getDeclaringClass() == Object.class) {
            return method.invoke(invoker, args);
        }
        if ("toString".equals(methodName) && parameterTypes.length == 0) {
            return invoker.toString();
        }
        if ("hashCode".equals(methodName) && parameterTypes.length == 0) {
            return invoker.hashCode();
        }
        if ("equals".equals(methodName) && parameterTypes.length == 1) {
            return invoker.equals(args[0]);
        }

        RpcInvocation invocation;
        if (RpcUtils.hasGeneratedFuture(method)) {
            Class<?> clazz = method.getDeclaringClass();
            String syncMethodName = methodName.substring(0, methodName.length() - Constants.ASYNC_SUFFIX.length());
            Method syncMethod = clazz.getMethod(syncMethodName, method.getParameterTypes());
            invocation = new RpcInvocation(syncMethod, args);
            invocation.setAttachment(Constants.FUTURE_GENERATED_KEY, "true");
            invocation.setAttachment(Constants.ASYNC_KEY, "true");
        } else {
            invocation = new RpcInvocation(method, args);
            if (RpcUtils.hasFutureReturnType(method)) {
                invocation.setAttachment(Constants.FUTURE_RETURNTYPE_KEY, "true");
                invocation.setAttachment(Constants.ASYNC_KEY, "true");
            }
        }

        // 此处的invoker为MockClusterInvoker
        return invoker.invoke(invocation).recreate();
    }


}
