import jwt



class token:
	
	def encode(classNo,password,key):
		encoded_data = jwt.encode(payload={"calssNo": classNo, "password": password},
								  key=key,
								  algorithm="HS256")

		return encoded_data



def decode(token: str,key):
    """
    :param token: jwt token
    :return:
    """
    decoded_data = jwt.decode(jwt=token,
                              key=key,
                              algorithms=["HS256"])

    return decoded_data
