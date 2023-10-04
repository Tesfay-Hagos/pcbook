gen:
	protoc --proto_path=proto --go_out=pb --go_opt=paths=source_relative processor_message.proto
clean:
	rm pb/*.go
run:
	go run main.go

.PHONY:gen clean run