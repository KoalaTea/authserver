package server

import "net/http"

type Server struct {

}

func New() Server {
	return Server{}
}

func (srv *Server) Run() {
	if err := http.ListenAndServe("0.0.0.0:80", nil); err != nil {
		panic(err)
	}
}