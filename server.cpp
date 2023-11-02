#include <iostream>
#include <string>
#include <thread>
#include <memory>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

using namespace boost::asio;

std::string generateResponse() {
    return "HTTP/1.1 204 No Content\r\n" \
                      "Connection: close\r\n" \
                      "\r\n";
}

void handleConnection(std::shared_ptr<ssl::stream<ip::tcp::socket>> clientSocket) {
    try {
        clientSocket->handshake(ssl::stream_base::server);

        while (true) {
            char data[1024];
            boost::system::error_code error;

            size_t bytesRead = clientSocket->read_some(buffer(data), error);

            if (error == boost::asio::error::eof) {
                break;
            } else if (error) {
                std::cerr << "Error receiving data: " << error.message() << std::endl;
                break;
            }
            std::string message(data, bytesRead);
            std::cout << "Received: " << message << std::endl;

            std::string response = generateResponse();

            // Send the "204 OK" response back to the client
            boost::asio::write(*clientSocket, buffer(response), error);

            if (error) {
                std::cerr << "Error sending response: " << error.message() << std::endl;
                break;
            }
        }
    } catch (std::exception& e) {
        std::cerr << "Exception in connection handling: " << e.what() << std::endl;
    }
}

int main() {
    io_context ioContext;
    ssl::context context(ssl::context::sslv23);
    boost::system::error_code ec;
        // Support only TLS v1.2 & v1.3
    context.set_options(boost::asio::ssl::context::default_workarounds |
                           boost::asio::ssl::context::no_sslv2 |
                           boost::asio::ssl::context::no_sslv3 |
                           boost::asio::ssl::context::single_dh_use |
                           boost::asio::ssl::context::no_tlsv1 |
                           boost::asio::ssl::context::no_tlsv1_1,
                       ec);
    if (ec)
    {
        std::cout<< "SSL context set_options failed";
        return -1;
    }
    context.set_verify_mode(boost::asio::ssl::verify_none, ec);
    context.use_certificate_chain_file("cert.pem");
    context.use_private_key_file("key.pem", ssl::context::pem);
    // All cipher suites are set as per OWASP datasheet.
    // https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cipher_String_Cheat_Sheet.html
    constexpr const char* sslCiphers = "ECDHE-ECDSA-AES128-GCM-SHA256:"
                                       "ECDHE-RSA-AES128-GCM-SHA256:"
                                       "ECDHE-ECDSA-AES256-GCM-SHA384:"
                                       "ECDHE-RSA-AES256-GCM-SHA384:"
                                       "ECDHE-ECDSA-CHACHA20-POLY1305:"
                                       "ECDHE-RSA-CHACHA20-POLY1305:"
                                       "DHE-RSA-AES128-GCM-SHA256:"
                                       "DHE-RSA-AES256-GCM-SHA384"
                                       "TLS_AES_128_GCM_SHA256:"
                                       "TLS_AES_256_GCM_SHA384:"
                                       "TLS_CHACHA20_POLY1305_SHA256";
    SSL_CTX_set_cipher_list(context.native_handle(), sslCiphers);
    ip::tcp::acceptor acceptor(ioContext, ip::tcp::endpoint(ip::tcp::v4(), 5555));

    while (true) {
        std::shared_ptr<ssl::stream<ip::tcp::socket>> clientSocket = std::make_shared<ssl::stream<ip::tcp::socket>>(ioContext, context);
        acceptor.accept(clientSocket->lowest_layer());

        // Create a new thread to handle the connection
        std::thread(handleConnection, clientSocket).detach();
    }

    return 0;
}
