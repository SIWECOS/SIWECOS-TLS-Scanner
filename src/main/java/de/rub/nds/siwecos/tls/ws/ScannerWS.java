/**
 *  SIWECOS-TLS-Scanner - A Webservice for the TLS-Scanner Module of TLS-Attacker
 *
 *  Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 */
package de.rub.nds.siwecos.tls.ws;

import de.rub.nds.siwecos.tls.DebugManager;
import de.rub.nds.siwecos.tls.TlsScannerCallback;
import de.rub.nds.siwecos.tls.constants.ScanType;
import static de.rub.nds.siwecos.tls.constants.ScanType.*;
import java.net.URISyntaxException;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import org.apache.logging.log4j.LogManager;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
@Path("/")
@Consumes(MediaType.APPLICATION_JSON)
public class ScannerWS {

    protected static final org.apache.logging.log4j.Logger LOGGER = LogManager.getLogger(ScannerWS.class.getName());

    @Context
    private UriInfo context;

    public ScannerWS() {
        Thread.currentThread().setName("Webservice-Thread");
    }

    @POST
    @Path("/https")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response scanHttps(ScanRequest request) throws URISyntaxException {
        LOGGER.info("Received a request to scan HTTPS of: " + request.getUrl());
        PoolManager
                .getInstance()
                .getService()
                .submit(new TlsScannerCallback(request, HTTPS, new DebugOutput(PoolManager.getInstance().getService()
                        .getQueue().size(), System.currentTimeMillis())));
        return Response.status(Response.Status.OK).entity("Success").type(MediaType.TEXT_PLAIN_TYPE).build();
    }

    @POST
    @Path("/smtp")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response scanSmtp(ScanRequest request) throws URISyntaxException {
        LOGGER.info("Received a request to scan SMTP(STARTTLS) of: " + request.getUrl());
        PoolManager
                .getInstance()
                .getService()
                .submit(new TlsScannerCallback(request, SMTP, new DebugOutput(PoolManager.getInstance().getService()
                        .getQueue().size(), System.currentTimeMillis())));
        return Response.status(Response.Status.OK).entity("Success").type(MediaType.TEXT_PLAIN_TYPE).build();
    }

    @POST
    @Path("/smtps")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response scanSmtps(ScanRequest request) throws URISyntaxException {
        LOGGER.info("Received a request to scan SMTP of: " + request.getUrl());
        PoolManager
                .getInstance()
                .getService()
                .submit(new TlsScannerCallback(request, SMTPS, new DebugOutput(PoolManager.getInstance().getService()
                        .getQueue().size(), System.currentTimeMillis())));
        return Response.status(Response.Status.OK).entity("Success").type(MediaType.TEXT_PLAIN_TYPE).build();
    }

    @POST
    @Path("/pop3")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response scanPop3(ScanRequest request) throws URISyntaxException {
        LOGGER.info("Received a request to scan POP3(STARTTLS) of: " + request.getUrl());
        PoolManager
                .getInstance()
                .getService()
                .submit(new TlsScannerCallback(request, POP3, new DebugOutput(PoolManager.getInstance().getService()
                        .getQueue().size(), System.currentTimeMillis())));
        return Response.status(Response.Status.OK).entity("Success").type(MediaType.TEXT_PLAIN_TYPE).build();
    }

    @POST
    @Path("/pop3s")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response scanPop3s(ScanRequest request) throws URISyntaxException {
        LOGGER.info("Received a request to scan POP3S of: " + request.getUrl());
        PoolManager
                .getInstance()
                .getService()
                .submit(new TlsScannerCallback(request, POP3S, new DebugOutput(PoolManager.getInstance().getService()
                        .getQueue().size(), System.currentTimeMillis())));
        return Response.status(Response.Status.OK).entity("Success").type(MediaType.TEXT_PLAIN_TYPE).build();
    }

    @POST
    @Path("/imap")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response scanImap(ScanRequest request) throws URISyntaxException {
        LOGGER.info("Received a request to scan IMAP(STARTTLS): " + request.getUrl());
        PoolManager
                .getInstance()
                .getService()
                .submit(new TlsScannerCallback(request, IMAP, new DebugOutput(PoolManager.getInstance().getService()
                        .getQueue().size(), System.currentTimeMillis())));
        return Response.status(Response.Status.OK).entity("Success").type(MediaType.TEXT_PLAIN_TYPE).build();
    }

    @POST
    @Path("/imaps")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response scanImaps(ScanRequest request) throws URISyntaxException {
        LOGGER.info("Received a request to scan IMAPS: " + request.getUrl());
        PoolManager
                .getInstance()
                .getService()
                .submit(new TlsScannerCallback(request, IMAPS, new DebugOutput(PoolManager.getInstance().getService()
                        .getQueue().size(), System.currentTimeMillis())));
        return Response.status(Response.Status.OK).entity("Success").type(MediaType.TEXT_PLAIN_TYPE).build();
    }

    @POST
    @Path("/mail")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response scanMail(ScanRequest request) throws URISyntaxException {
        LOGGER.info("Received a request to scan IMAPS: " + request.getUrl());
        PoolManager
                .getInstance()
                .getService()
                .submit(new TlsScannerCallback(request, MAIL, new DebugOutput(PoolManager.getInstance().getService()
                        .getQueue().size(), System.currentTimeMillis())));
        return Response.status(Response.Status.OK).entity("Success").type(MediaType.TEXT_PLAIN_TYPE).build();
    }

    @POST
    @Path("/poolconfig")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response changePoolSize(PoolsizeChangeRequest poolsizeChangeRequest) throws URISyntaxException {
        LOGGER.info("Changed Poolsize to: " + poolsizeChangeRequest.getSize());
        PoolManager.getInstance().setPoolSize(poolsizeChangeRequest.getSize());
        return Response.status(Response.Status.OK).entity("Poolsize Changed to " + poolsizeChangeRequest.getSize())
                .type(MediaType.TEXT_PLAIN_TYPE).build();
    }

    @POST
    @Path("/taskpool")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response getTaskPoolSize() throws URISyntaxException {
        long poolsize = PoolManager.getInstance().getService().getQueue().size();
        LOGGER.info("Returning requested task pool size: " + poolsize);
        return Response.status(Response.Status.OK).entity("Current Tasks in queue: " + poolsize)
                .type(MediaType.TEXT_PLAIN_TYPE).build();
    }

    @POST
    @Path("/toggleDebug")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response getToggleDebug() throws URISyntaxException {
        DebugManager.getInstance().setDebugEnabled(!DebugManager.getInstance().isDebugEnabled());
        if (DebugManager.getInstance().isDebugEnabled()) {
            LOGGER.info("Switched DebugMode on");
            return Response.status(Response.Status.OK).entity("Switched DebugMode on").type(MediaType.TEXT_PLAIN_TYPE)
                    .build();
        } else {
            LOGGER.info("Switched DebugMode off");
            return Response.status(Response.Status.OK).entity("Switched DebugMode off").type(MediaType.TEXT_PLAIN_TYPE)
                    .build();
        }
    }
}
