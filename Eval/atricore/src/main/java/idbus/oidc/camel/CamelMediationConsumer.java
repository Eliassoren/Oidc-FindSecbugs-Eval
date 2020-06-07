package idbus.oidc.camel;


import org.apache.camel.Endpoint;
import org.apache.camel.Processor;
import org.apache.camel.impl.DefaultConsumer;

/**
 * @author <a href="mailto:sgonzalez@atricore.org">Sebastian Gonzalez Oyuela</a>
 * @version $Id$
 */
public class CamelMediationConsumer<E extends CamelMediationExchange> extends DefaultConsumer<E> {

    public CamelMediationConsumer(Endpoint<E> camelMediationExchangeEndpoint, Processor processor) {
        super(camelMediationExchangeEndpoint, processor);
    }


}

