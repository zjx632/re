在remain函数的最后加入下面两句, 消除内存泄露
	pthread_mutex_destroy(&re->mutex);

	pthread_key_delete(pt_key);