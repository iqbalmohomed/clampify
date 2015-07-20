screen -d -m -S clampify
screen -S clampify -p 0 -X chdir ~/gocode/src/clampify
screen -S clampify -p 0 -X exec go run clampify.go watch demo-net
#sleep 1
#screen -S orion -X screen SOMETHING_ELSE
