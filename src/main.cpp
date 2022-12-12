/*
	mingw : pacman -S --needed base-devel mingw-w64-x86_64-boost mingw-w64-x86_64-cmake mingw-w64-x86_64-toolchain mingw-w64-x86_64-asio libssh
*/



#include "Simple-Web-Server/server_http.hpp"
#include <future>



// Added for the default_resource example
#include <algorithm>

#include <fstream>
#include <vector>





#include "utils.h"
#include "rapidjson/document.h"



using namespace std;

using HttpServer = SimpleWeb::Server<SimpleWeb::HTTP>;







#include <libssh2.h>

#include <map>






struct db_t
{
	int sock;
	struct sockaddr_in sin;
	LIBSSH2_SESSION *session;
	LIBSSH2_CHANNEL *channel;
	int rc;
};




map<uint32_t, db_t> db;


bool SSH_Connect(db_t &db, const char *hostname, uint16_t port, const char *username, const char *password);
bool SSH_Send(db_t &db, const char *commandline);
bool SSH_Disconect(db_t &db);





bool SSH_Connect(db_t &db, const char *hostname, uint16_t port, const char *username, const char *password)
{

	unsigned long hostaddr;

    #ifdef WIN32
    WSADATA wsadata;
    int err;

    err = WSAStartup(MAKEWORD(2, 0), &wsadata);
    if(err != 0) {
        fprintf(stderr, "WSAStartup failed with error: %d\n", err);
        return 1;
    }
#endif



    db.rc = libssh2_init(0);
    if(db.rc != 0) {
        fprintf(stderr, "libssh2 initialization failed (%d)\n", db.rc);
        return 1;
    }

    hostaddr = inet_addr(hostname);

    /* Ultra basic "connect to port 22 on localhost"
     * Your code is responsible for creating the socket establishing the
     * connection
     */
    db.sock = socket(AF_INET, SOCK_STREAM, 0);

    db.sin.sin_family = AF_INET;
    db.sin.sin_port = htons(port);
    db.sin.sin_addr.s_addr = hostaddr;
    if(connect(db.sock, (struct sockaddr*)(&db.sin),
                sizeof(struct sockaddr_in)) != 0) {
        fprintf(stderr, "failed to connect!\n");
        return -1;
    }

    /* Create a session instance */
    db.session = libssh2_session_init();
    if(!db.session)
        return -1;

    /* tell libssh2 we want it all done non-blocking */
    libssh2_session_set_blocking(db.session, 0);

    /* ... start it up. This will trade welcome banners, exchange keys,
     * and setup crypto, compression, and MAC layers
     */
    while((db.rc = libssh2_session_handshake(db.session, db.sock)) ==
           LIBSSH2_ERROR_EAGAIN);
    if(db.rc) {
        fprintf(stderr, "Failure establishing SSH session: %d\n", db.rc);
        return -1;
    }



        /* We could authenticate via password */
        while((db.rc = libssh2_userauth_password(db.session, username, password)) == LIBSSH2_ERROR_EAGAIN);
        if(db.rc) {
            fprintf(stderr, "Authentication by password failed.\n");
            //goto shutdown;
        }




	return true;
}

bool SSH_Send(db_t &db, const char *commandline, string &response)
{

    /* Exec non-blocking on the remove host */
    while((db.channel = libssh2_channel_open_session(db.session)) == NULL && libssh2_session_last_error(db.session, NULL, NULL, 0) == LIBSSH2_ERROR_EAGAIN)
    {
        waitsocket(db.sock, db.session);
    }
    
    if(db.channel == NULL) {
        fprintf(stderr, "Error\n");
        //exit(1);
		SSH_Disconect(db);
    }

	while((db.rc = libssh2_channel_exec(db.channel, commandline)) == LIBSSH2_ERROR_EAGAIN)
	{
        waitsocket(db.sock, db.session);
    }

    if(db.rc != 0) {
        fprintf(stderr, "Error\n");
        //exit(1);
		SSH_Disconect(db);
    }
    for(;;) {
        /* loop until we block */
        int rc;
        do {
            char buffer[0x4000];
            rc = libssh2_channel_read(db.channel, buffer, sizeof(buffer) );
            if(rc > 0) {

				response.append(buffer, rc);

				/*
                int i;
                fprintf(stderr, "We read:\n");
                for(i = 0; i < rc; ++i)
                    fputc(buffer[i], stderr);
                fprintf(stderr, "\n");
				*/
            }
            else {
                if(rc != LIBSSH2_ERROR_EAGAIN)
                    /* no need to output this for the EAGAIN case */
                    fprintf(stderr, "libssh2_channel_read returned %d\n", rc);
            }
        }
        while(rc > 0);

        /* this is due to blocking that would occur otherwise so we loop on
           this condition */
        if(rc == LIBSSH2_ERROR_EAGAIN) {
            waitsocket(db.sock, db.session);
        }
        else
            break;
    }

	while((db.rc = libssh2_channel_close(db.channel)) == LIBSSH2_ERROR_EAGAIN)
	{
		waitsocket(db.sock, db.session);
	}

	return true;
}

bool SSH_Disconect(db_t &db)
{

	//int exitcode;
    //char *exitsignal = (char *)"none";

	   //exitcode = 127;


    if(db.rc == 0) {
        //exitcode = libssh2_channel_get_exit_status(db.channel);
        //libssh2_channel_get_exit_signal(db.channel, &exitsignal, NULL, NULL, NULL, NULL, NULL);
    }

    libssh2_channel_free(db.channel);
    db.channel = NULL;

//shutdown:

    libssh2_session_disconnect(db.session, "Normal Shutdown, Thank you for playing");
    libssh2_session_free(db.session);

#ifdef WIN32
    closesocket(db.sock);
#else
    close(db.sock);
#endif
    //fprintf(stderr, "all done\n");

    //libssh2_exit();

	return true;
}





































































using namespace rapidjson;

struct query_t
{
	string type;	// Тип сервера, пока только 'ssh'.
	string host;	// Хост сервера, ИМЯ или IP.
	uint16_t port;	// Порт сервера.
	string login;	// Логин пользователя.
	string pass;	// Пароль пользователя.
	string cmd;		// Выполняемая команда.
	string format;	// Формат ответа, пока только 'raw-string'.
	bool close;		// Флаг, указывающий на то, что нужно закрыть соединение после выполннения команды, иначе - сохранить.
	
	uint32_t hash;	// Уникальный хеш соединения (host+port+login+pass).
};

void JSON_Parse(string json_str, query_t &obj)
{
	Document json;
	json.Parse( json_str.c_str() );
	
	obj.type = json["type"].GetString();
	obj.host = json["host"].GetString();
	obj.port = json["port"].GetUint();
	obj.login = json["login"].GetString();
	obj.pass = json["pass"].GetString();
	obj.cmd = json["cmd"].GetString();
	obj.format = json["format"].GetString();
	obj.close = json["close"].GetBool();
	
	string hash_str = obj.host + to_string(obj.port) + obj.login + obj.pass;
	obj.hash = JSHash(hash_str);
	
	return;
}






int main() {
  // HTTP-server at port 8080 using 1 thread
  // Unless you do more heavy non-threaded processing in the resources,
  // 1 thread is usually faster than several threads
  HttpServer server;
  server.config.port = 8080;


	/*
		RESTer: https://addons.mozilla.org/ru/firefox/addon/rester/
		URL: http://127.0.0.1:8080/json
		Data, POST:
{
  "type": "ssh",
  "host": "10.0.1.1",
  "port": 22,
  "login": "test_ssh_user",
  "pass": "1q2w3e4r",
  "cmd": "/interface monitor-traffic ISP-OPCOM once without-paging;",
  "format": "raw_string",
  "close": false
}
	*/
	server.resource["^/json$"]["POST"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request)
	{
		try
		{
			query_t obj;
			JSON_Parse(request->content.string(), obj);

			/*
				1. Ищем сессию по obj.hash.
					если нету, то создаём новую и подключаемся.
					если есть то используем старую.
				2. Выполняем команду.
				3. Отвечаем согласно obj.format.
				4. Если obj.close == true, то закрываем сессию, иначе сохраняем и поддерживаем.
			*/

			



			db_t db_el;
			auto pos = db.find(obj.hash);
			if(pos == db.end())
			{
				fprintf(stderr, "Create session\n");

				// Сессия не найдена, нужно создать.
				SSH_Connect(db_el, obj.host.c_str(), obj.port, obj.login.c_str(), obj.pass.c_str());
				db.emplace(obj.hash, db_el);
			}
			else
			{
				fprintf(stderr, "Use session\n");

				// Сессия найдена, нужно использовать.
				db_el = pos->second;
			}
			
			
			//string response(22, '*');
			string ssh_response;
			SSH_Send(db_el, obj.cmd.c_str(), ssh_response);
			
			
			response->write(SimpleWeb::StatusCode::success_ok, ssh_response);







			
			
			/*
			if(obj.type == "ssh")
			{
				//

				if(obj.format == "raw_string")
				{

				}
				else
				{
					response->write(SimpleWeb::StatusCode::client_error_method_not_allowed, "'format' = 'raw_string' only");
				}
			}
			else
			{
				response->write(SimpleWeb::StatusCode::client_error_method_not_allowed, "'type' = 'ssh' only");
			}
			*/




			//response->write("ЭЭ");
		}
		catch(const exception &e)
		{
			response->write(SimpleWeb::StatusCode::client_error_bad_request, e.what());
		}
	};

  // GET-example for the path /info
  // Responds with request-information
  server.resource["^/info$"]["GET"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
    stringstream stream;
    stream << "<h1>Request from " << request->remote_endpoint().address().to_string() << ":" << request->remote_endpoint().port() << "</h1>";

    stream << request->method << " " << request->path << " HTTP/" << request->http_version;

    stream << "<h2>Query Fields</h2>";
    auto query_fields = request->parse_query_string();
    for(auto &field : query_fields)
      stream << field.first << ": " << field.second << "<br>";

    stream << "<h2>Header Fields</h2>";
    for(auto &field : request->header)
      stream << field.first << ": " << field.second << "<br>";

    response->write(stream);
  };

  // GET-example simulating heavy work in a separate thread
  server.resource["^/work$"]["GET"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> /*request*/) {
    thread work_thread([response] {
      this_thread::sleep_for(chrono::seconds(5));
      response->write("Work done");
    });
    work_thread.detach();
  };

  server.on_error = [](shared_ptr<HttpServer::Request> /*request*/, const SimpleWeb::error_code & /*ec*/) {
    // Handle errors here
    // Note that connection timeouts will also call this handle with ec set to SimpleWeb::errc::operation_canceled
  };

  // Start server and receive assigned port when server is listening for requests
  promise<unsigned short> server_port;
  thread server_thread([&server, &server_port]() {
    // Start server
    server.start([&server_port](unsigned short port) {
      server_port.set_value(port);
    });
  });
  cout << "Server listening on port " << server_port.get_future().get() << endl
       << endl;

  server_thread.join();
}
