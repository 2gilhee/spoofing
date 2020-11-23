main: main.cpp hackARP.cpp
	# g++ -o hackARP hackARP.cpp -lpcap
	g++ -o main main.cpp hackARP.cpp -lpcap -pthread
