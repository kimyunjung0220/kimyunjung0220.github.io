---
layout: post
title: "Level 3: Pybrid"
date: 2025-05-14
category: Python
image: assets/img/blog/wargame.png
author: 김윤중
tags: Python class pollution, JS Prototype Pollution
---


## 3️⃣ Pybrid

## Description
Description (ko)
조직을 관리하기 위한 간단한 서비스입니다.

서비스의 취약점을 찾고 익스플로잇하여 플래그를 획득하세요!

플래그 형식은 DH{...} 입니다.

## 🔍 End Point 분석

<pre>
from flask import Flask, request, jsonify, render_template, redirect, url_for
from os import popen

app = Flask(__name__)

class Student: 
    def __init__(self, name):
        self.name = name
        self.role = "student"

class Teacher(Student): 
    def __init__(self, name):
        super().__init__(name)
        self.role = "teacher"

class SubstituteTeacher(Teacher): 
    def __init__(self, name):
        super().__init__(name)
        self.role = "substitute_teacher"

class Principal(Teacher): 
    def __init__(self, name):
        super().__init__(name)
        self.role = "principal"

    def command(self):
        command = self.cmd if hasattr(self, 'cmd') else 'echo Permission Denied'
        return f'{popen(command).read().strip()}'
</pre>

조직을 관리하기 위해 조직 클래스가 정의되어 있습니다.  
각 클래스는 자신의 상단 클래스를 상속 받고 있으며,  

교장의 클래스는 커멘드를 실행할 수 있도록 command
메서드가 만들어져 있습니다. 이를 통하여 cmd 속성이  
만들어지면 명령어를 실행할 수 있게 되는 구조입니다.



<pre>
def merge(src, dst):
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))
        else:
            setattr(dst, k, v)
</pre>



merge 함수를 통하여 사용자가 입력한 값을 **검증없이** setattr함수를 통하여  
속성을 정의해 줍니다. 이를 통하여 cmd 속성을 만들 수 있게 되어 시스템 명령어가  
실행될 수 있는 아주 취약한 구성을 가지고 있습니다.  


<pre>

principal = Principal("principal")
members = []
members.append({"name":"admin", "role":"principal"})

@app.route('/')
def index():
    return render_template('index.html', members=members)

@app.route('/execute', methods=['GET'])
def execute():
    return jsonify({"result": principal.command()})

@app.route('/add_member', methods=['GET', 'POST'])
def add_member():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form
        
        name = data.get("name")
        role = data.get("role")
        
        if role == "teacher":
            new_member = Teacher(name)
        elif role == "student":
            new_member = Student(name)
        elif role == "substitute_teacher":
            new_member = SubstituteTeacher(name)
        elif role == "principal":
            new_member = Principal(name)
            merge(data, new_member)
        else:
            return jsonify({"message": "Invalid role"}), 400
        
        members.append({"name": new_member.name, "role": new_member.role})
        return redirect(url_for('index'))
    return render_template('add_member.html')

@app.route('/members', methods=['GET'])
def get_members():
    return jsonify({"members": members})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

</pre>



서버측 구조입니다. 
/execute 페이지로 이미 정의된 principal 객체의 command 메서드를 통하여  
명령어를 실행하여 결과를 반환해줍니다. 

/add_member 페이지를 통하여 새로운 멤버를  
추가할 수 있으며, 최고 등급인 principal의 멤버도 추가할 수 있다는 걸  
확인하였습니다. 

## ✏️ 풀이 작성

단순히 /add_member페이지를 통하여 principal 객체에 cmd속성을 추가해주면  
될 거 같지만 사용자가 멤버를 추가하기 전 principal객체는 이미 정의가 되어  
있기에 cmd를 만들어 준다고 해서 cmd값을 가져와 명령이 실행될 일은 없습니다.  

Class를 오염시키는 방법을 공략해볼 수 있습니다.
<pre>
class hello():
    def __init__(self):
        self.msg = "안녕하세요."

obj1 = hello()
obj2 = hello()

obj2.msg = "안녕히가세요"

print(obj1.msg)
print(obj2.msg)

setattr(obj1.__class__, "tt", "객체의 메타데이터가 오염되었습니다.")

print(obj1.tt)
print(obj2.tt)
</pre>

python의 class를 오염시키는 샘플코드 입니다.  
<pre> 
실행 결과 : 
안녕하세요.
안녕히가세요
객체의 메타데이터가 오염되었습니다.
객체의 메타데이터가 오염되었습니다.
</pre>

Reference : https://blog.abdulrah33m.com/prototype-pollution-in-python/
## 💡 알게된 점
JS에 있는 Prototype 오염과 유사하게 작동이 됩니다.  
하나의 메타데이터를 오염시키면 모든 객체가 오염이 되어 상황에 따라 치명적으로  
작동할 수 있기에 사용자가 입력한 값을 검증없이 추가하지 않도록 하는게 중요합니다.  

## ✔️ 답안

DreamHack 정책으로 인하여 답안은 제공되지, 풀이 결과는 제공되지 않습니다.  
힌트는 드림핵 공식 홈페이지에서 질문을 올리시거나, 유료 답안을 구매하시길
바랍니다.

Date : 2025-05-14 Wed
